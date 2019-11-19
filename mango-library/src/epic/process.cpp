#include "../../include/epic/process.h"

#include <iostream>
#include <algorithm>
#include <Psapi.h>

#include "../../include/epic/shellcode.h"
#include "../../include/epic/syscalls.h"
#include "../../include/epic/windows_defs.h"

#include "../../include/misc/misc.h"
#include "../../include/misc/error_codes.h"
#include "../../include/misc/logger.h"


namespace {
	// iterate over every module in the process
	template <typename Ptr, typename Callable>
	void iterate_modules(const mango::Process& process, Callable&& callback) {
		using namespace mango;

		// get the corresponding peb structure for the process (32bit vs 64bit)
		_PEB_INTERNAL<Ptr> peb;
		if constexpr (sizeof(Ptr) == 4)
			peb = process.get_peb32();
		else
			peb = process.get_peb64();

		// PEB_LDR_DATA
		const auto list_head = process.read<_PEB_LDR_DATA_INTERNAL<Ptr>>(peb.Ldr).InMemoryOrderModuleList;
		for (auto current = list_head.Flink; current != list_head.Blink;) {
			// LDR_DATA_TABLE_ENTRY
			const auto table_addr = current - offsetof(_LDR_DATA_TABLE_ENTRY_INTERNAL<Ptr>, InMemoryOrderLinks);
			const auto table_entry = process.read<_LDR_DATA_TABLE_ENTRY_INTERNAL<Ptr>>(table_addr);

			const auto name_addr = uintptr_t(table_entry.FullDllName.Buffer);
			const auto name_size = size_t(table_entry.FullDllName.Length);

			// read the dll name
			const auto name_wstr = std::make_unique<wchar_t[]>(name_size + 1);
			process.read(name_addr, name_wstr.get(), name_size);
			name_wstr[name_size] = L'\0';

			// call our callback
			std::invoke(callback, wstr_to_str(name_wstr.get()), table_entry.DllBase);

			// proceed to next entry
			current = process.read<_LIST_ENTRY_INTERNAL<Ptr>>(current).Flink;
		}
	}
} // namespace

namespace mango {
	// setup by pid
	void Process::setup(const uint32_t pid, const SetupOptions& options) {
		this->release();

		// set debug privileges
		Process::set_debug_privilege(true);
		ScopeGuard _guard(&Process::set_debug_privilege, false);

		// parameters for NtOpenProcess()
#pragma warning(suppress: 4312) // conversion from 'const uint32_t' to 'PVOID' of greater size
		CLIENT_ID client_id = { PVOID(pid) };
		OBJECT_ATTRIBUTES object_attributes = { sizeof(object_attributes) };

		// open a handle to the process
		const auto status = NtOpenProcess(&this->m_handle, options.m_handle_access, &object_attributes, &client_id);
		if (!NT_SUCCESS(status))
			throw InvalidProcessHandle(mango_format_ntstatus(status));

		this->m_options = options;
		this->m_free_handle = true;

		// this can throw
		this->setup_internal();
	}

	// setup using an existing handle (must have atleast PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
	void Process::setup(const HANDLE handle, const SetupOptions& options) {
		this->release();

		this->m_options = options;
		this->m_handle = handle;
		this->m_free_handle = false;

		// this can throw
		this->setup_internal();
	}

	// clean up
	void Process::release() noexcept {
		if (!this->m_is_valid)
			return;

		// never throw in a destructor
		try {
			if (this->m_free_handle)
				CloseHandle(this->m_handle);
		} catch (...) {}

		this->m_is_valid = false;
	}

	// get a loaded module, case-insensitive (passing "" for name returns the current process module)
	const LoadedModule* Process::get_module(std::string name) const {
		// return own module
		if (name.empty())
			name = this->get_name();

		// change to lowercase
		std::transform(name.begin(), name.end(), name.begin(), std::tolower);

		// find the module
		if (const auto& it = this->m_modules.find(name); it != this->m_modules.end())
			return &it->second;
		
		// not using defer loading
		if (!this->m_options.m_defer_module_loading)
			return nullptr;

		// module might not be loaded yet (defer loading option)
		if (const auto& it = this->m_module_addresses.find(name); it != this->m_module_addresses.end())
			return &(this->m_modules[it->first] = LoadedModule(*this, it->second));
		return nullptr;
	}

	// get the base address of a module
	uintptr_t Process::get_module_addr(const std::string& module_name) const {
		if (const auto mod = this->get_module(module_name); mod)
			return mod->get_image_base();
		return 0;
	}

	// this uses the internal list of modules to find the function address
	// not as consistant as the implementation below but probably faster
	uintptr_t Process::get_proc_addr(const std::string& module_name, const std::string& func_name) const {
		const auto mod = this->get_module(module_name);
		if (!mod)
			return 0;

		const auto exp = mod->get_export(func_name);
		if (!exp)
			return 0;

		return exp->m_address;
	}

	// peb structures
	PEB_M32 Process::get_peb32() const {
		if (this->is_64bit())
			throw NotA32BitProcess();
		return this->read<PEB_M32>(this->m_peb64_address + 0x1000);
	}
	PEB_M64 Process::get_peb64() const {
		return this->read<PEB_M64>(this->m_peb64_address);
	}

	// read from a memory address
	void Process::read(const void* const address, void* const buffer, const size_t size) const {
		this->m_options.m_read_memory_func(this, address, buffer, size);
	}

	// write to a memory address
	void Process::write(void* const address, const void* const buffer, const size_t size) const {
		this->m_options.m_write_memory_func(this, address, buffer, size);
	}

	// allocate virtual memory in the process (wrapper for VirtualAllocEx)
	void* Process::alloc_virt_mem(const size_t size, const uint32_t protection, const uint32_t type) const {
		return this->m_options.m_allocate_memory_func(this, size, protection, type);
	}

	// free virtual memory in the process (wrapper for VirtualFreeEx)
	void Process::free_virt_mem(void* const address, const size_t size, const uint32_t type) const {
		this->m_options.m_free_memory_func(this, address, size, type);
	}

	// get the protection of a page of memory
	uint32_t Process::get_mem_prot(void* const address) const {
		MEMORY_BASIC_INFORMATION buffer;
		if (const auto status = NtQueryVirtualMemory(this->m_handle, address, MemoryBasicInformation, &buffer, sizeof(buffer), nullptr); !NT_SUCCESS(status))
			throw FailedToQueryMemoryProtection(mango_format_ntstatus(status));
		return buffer.Protect;
	}

	// set the protection, returns the old protection
	uint32_t Process::set_mem_prot(void* address, const size_t size, const uint32_t protection) const {
		DWORD OldAccessProtection = 0;
		SIZE_T NumberOfBytesToProtect = size;
		if (const auto status = NtProtectVirtualMemory(this->m_handle, &address, &NumberOfBytesToProtect, protection, &OldAccessProtection); !NT_SUCCESS(status))
			throw FailedToSetMemoryProtection(mango_format_ntstatus(status));
		return OldAccessProtection;
	}

	// wrapper over CreateRemoteThread (will wait infinitely for the thread to finish)
	void Process::create_remote_thread(void* const address, void* const argument) const {
		this->m_options.m_create_remote_thread_func(this, address, argument);
	}

	// suspend/resume the process
	void Process::suspend() const {
		if (const auto status = NtSuspendProcess(this->m_handle); !NT_SUCCESS(status))
			throw FailedToSuspendProcess(mango_format_ntstatus(status));
	}
	void Process::resume() const {
		if (const auto status = NtResumeProcess(this->m_handle); !NT_SUCCESS(status))
			throw FailedToResumeProcess(mango_format_ntstatus(status));
	}

	// get the handles that the process currently has open
	Process::ProcessHandles Process::get_open_handles() const {
		unsigned long buffer_size = 0xFFFF;
		uint8_t* buffer = new uint8_t[buffer_size];

		// make sure we delete the fat chunk of memory
		ScopeGuard _guard([&]() { delete[] buffer; });

		// query system info
		NTSTATUS status = 0;
		while ((status = mango::NtQuerySystemInformation(SystemHandleInformation, buffer, buffer_size, nullptr)) == 0xC0000004) {
			// buffer too small; allocate larger
			delete[] buffer; buffer = new uint8_t[buffer_size *= 2];
		}

		// failure
		if (!NT_SUCCESS(status))
			throw FailedToQuerySystemInformation(mango_format_ntstatus(status));

		std::vector<HandleInfo> handles;

		// filter out handles to the process
		const auto handle_info = PSYSTEM_HANDLE_INFORMATION(buffer);
		for (size_t i = 0; i < handle_info->HandleCount; ++i) {
			const auto entry = handle_info->Handles[i];

			// we only care about this process
			if (entry.ProcessId != this->m_pid)
				continue;

			handles.push_back({ HANDLE(entry.Handle), entry.ObjectTypeNumber, entry.GrantedAccess });
		}

		return handles;
	}

	// updates the internal list of modules
	void Process::load_modules() {
		// update addresses
		this->query_module_addresses();

		// clear any previously loaded modules
		this->m_modules.clear();

		// load every module
		for (const auto& [name, address] : this->m_module_addresses)
			this->m_modules[name] = LoadedModule(*this, address);
	}

	// SeDebugPrivilege
	void Process::set_debug_privilege(const bool value) {
		// get a process token handle
		HANDLE token_handle = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token_handle))
			throw FailedToOpenProcessToken(mango_format_w32status(GetLastError()));

		// close handle when we're done
		ScopeGuard _guard(&CloseHandle, token_handle);

		// get the privilege luid
		LUID luid;
		if (!LookupPrivilegeValueA(0, enc_str("SeDebugPrivilege").c_str(), &luid))
			throw FailedToGetPrivilegeLUID(mango_format_w32status(GetLastError()));

		TOKEN_PRIVILEGES token_privileges;
		token_privileges.PrivilegeCount = 1;
		token_privileges.Privileges[0].Luid = luid;
		token_privileges.Privileges[0].Attributes = value ? SE_PRIVILEGE_ENABLED : 0;

		// the goob part
		if (!AdjustTokenPrivileges(token_handle, false, &token_privileges, 0, 0, 0))
			throw FailedToSetTokenPrivilege(mango_format_w32status(GetLastError()));
	}

	// get the name of the process (to cache it)
	std::string Process::query_name() const {
		char buffer[1024];
		if (DWORD size = sizeof(buffer); !QueryFullProcessImageName(this->m_handle, 0, buffer, &size))
			throw FailedToQueryProcessName(mango_format_w32status(GetLastError()));

		std::string name(buffer);

		// erase everything before the last back slash
		const size_t pos = name.find_last_of('\\');
		if (pos != std::string::npos)
			name = name.substr(pos + 1);

		return name;
	}

	// wow64 process
	bool Process::query_is_wow64() const {
		// check if Wow64 is present
		BOOL is_wow64 = false;
		if (!IsWow64Process(this->m_handle, &is_wow64))
			throw FailedToQueryProcessArchitecture(mango_format_w32status(GetLastError()));

		return is_wow64;
	}

	// check whether the process is 64bit or not (to cache it)
	bool Process::query_is_64bit() const {
		// 32bit process on 64bit os
		if (this->m_is_wow64)
			return false;

		SYSTEM_INFO system_info;
		GetNativeSystemInfo(&system_info);
		return system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
	}

	// update the internal list of module addresses
	void Process::query_module_addresses() {
		// clear any previous module addresses
		this->m_module_addresses.clear();

		const auto callback = [&](auto name, const auto base) {
			// remove everything before the filename
			if (const auto index = name.find_last_of('\\'); index != std::string::npos)
				name.erase(name.begin(), name.begin() + index + 1);

			// change to lowercase
			std::transform(name.begin(), name.end(), name.begin(), std::tolower);

			//logger.info(name, ":0x", std::hex, std::uppercase, base);
			this->m_module_addresses[name] = uintptr_t(base);
		};

		if (this->is_64bit()) {
			iterate_modules<uint64_t>(*this, callback);
		} else {
			iterate_modules<uint32_t>(*this, callback);
		}
	}

	// the address of the 64bit peb
	uintptr_t Process::query_peb64_address() const {
		PROCESS_BASIC_INFORMATION info;
		if (const auto status = mango::NtQueryInformationProcess(this->m_handle, ProcessBasicInformation, &info, sizeof(info), nullptr); !NT_SUCCESS(status))
			throw FailedToQueryProcessInformation(mango_format_ntstatus(status));

		if (sizeof(void*) == 8) { // host is a 64bit process
			return uintptr_t(info.PebBaseAddress);
		} else /* host is a 32bit process */ {
			return uintptr_t(info.PebBaseAddress) - 0x1000;
		}
	}

	// used by setup()
	void Process::setup_internal() {
		// properly cleanup if an exception is thrown
		ScopeGuard _guard(&Process::release, this);

		this->m_is_valid = true;
		this->m_pid = GetProcessId(this->m_handle);
		this->m_is_self = (this->m_pid == GetCurrentProcessId());

		// cache some info
		this->m_is_wow64 = this->query_is_wow64();
		this->m_is_64bit = this->query_is_64bit();

		// access a 64bit program from a 32bit program
		if (sizeof(void*) == 4 && this->m_is_64bit)
			throw CantSetup64From32();

		this->m_process_name = this->query_name();
		this->m_peb64_address = this->query_peb64_address();

		// update the internal list of modules
		if (!this->m_options.m_defer_module_loading)
			this->load_modules();
		else
			this->query_module_addresses();

		// no exception was thrown, great
		_guard.cancel();
	}

	// override to change internal behavior
	void Process::default_read_memory_func(const Process* const process, const void* const address, void* const buffer, const size_t size) {
		if (process->is_self()) {
			if (memcpy_s(buffer, size, address, size))
				throw FailedToReadMemory();
		} else if (const auto status = NtReadVirtualMemory(process->get_handle(), address, buffer, size, nullptr); !NT_SUCCESS(status)) {
			throw FailedToReadMemory(mango_format_ntstatus(status));
		}
	}
	void Process::default_write_memory_func(const Process* const process, void* const address, const void* const buffer, const size_t size) {
		if (process->is_self()) {
			if (memcpy_s(address, size, buffer, size))
				throw FailedToWriteMemory();
		} else if (const auto status = NtWriteVirtualMemory(process->get_handle(), address, buffer, size, nullptr); !NT_SUCCESS(status)) {
			throw FailedToWriteMemory(mango_format_ntstatus(status));
		}
	}
	void* Process::default_allocate_memory_func(const Process* const process, const size_t size, const uint32_t protection, const uint32_t type) {
		void* address = nullptr; SIZE_T region_size = size;
		if (const auto status = NtAllocateVirtualMemory(process->get_handle(), &address, 0, &region_size, type, protection); !NT_SUCCESS(status))
			throw FailedToAllocateVirtualMemory(mango_format_ntstatus(status));
		return address;
	}
	void Process::default_free_memory_func(const Process* const process, void* const address, const size_t size, const uint32_t type) {
		void* base_address = address; SIZE_T region_size = size;
		if (const auto status = NtFreeVirtualMemory(process->get_handle(), &base_address, &region_size, type); !NT_SUCCESS(status))
			throw FailedToFreeVirtualMemory(mango_format_ntstatus(status));
	}
	void Process::default_create_remote_thread_func(const Process* const process, void* const address, void* const argument) {
		HANDLE thread_handle;
		if (const auto status = NtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS, nullptr, process->get_handle(), address, argument, 0, 0, 0, 0, nullptr); !NT_SUCCESS(status))
			throw FailedToCreateRemoteThread(mango_format_ntstatus(status));

		WaitForSingleObject(thread_handle, INFINITE);
		CloseHandle(thread_handle);
	}
} // namespace mango