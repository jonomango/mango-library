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


namespace mango {
	// setup by pid
	void Process::setup(const uint32_t pid, const SetupOptions& options) {
		this->release();

		this->set_debug_privilege(true);

		// open a handle to the process
		this->m_handle = OpenProcess(
			PROCESS_VM_READ | // ReadProcessMemory
			PROCESS_VM_WRITE | // WriteProcessMemory
			PROCESS_VM_OPERATION | // VirtualAllocEx / VirtualProtectEx
			PROCESS_QUERY_INFORMATION | // QueryFullProcessImageName
			PROCESS_CREATE_THREAD, // CreateRemoteThread
			FALSE, pid
		);

		this->set_debug_privilege(false);

		// whether we're valid or not depends entirely on OpenProcess()
		if (this->m_handle == nullptr)
			throw InvalidProcessHandle();

		this->m_options = options;
		this->m_free_handle = true;
		
		// properly cleanup if an exception is thrown
		mango::ScopeGuard _guard(&Process::release, this);

		// this can throw
		this->setup_internal();

		// no exception was thrown, great
		_guard.cancel();
	}

	// setup using an existing handle (must have atleast PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
	void Process::setup(const HANDLE handle, const SetupOptions& options) {
		this->release();

		this->m_options = options;
		this->m_handle = handle;
		this->m_free_handle = false;

		// properly cleanup if an exception is thrown
		mango::ScopeGuard _guard(&Process::release, this);

		// this can throw
		this->setup_internal();

		// no exception was thrown, great
		_guard.cancel();
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
	PEB32 Process::get_peb32() const {
		if (this->is_64bit())
			throw NotA32BitProcess();
		return this->read<PEB32>(this->m_peb64_address + 0x1000);
	}
	PEB64 Process::get_peb64() const {
		return this->read<PEB64>(this->m_peb64_address);
	}

	// read from a memory address
	void Process::read(const void* const address, void* const buffer, const size_t size) const {
		if (this->is_self()) {
			if (memcpy_s(buffer, size, address, size))
				throw FailedToReadMemory();
		} else if (!NT_SUCCESS(NtReadVirtualMemory(this->m_handle, address, buffer, size, nullptr))) {
			throw FailedToReadMemory();
		}
	}

	// write to a memory address
	void Process::write(void* const address, const void* const buffer, const size_t size) const {
		if (this->is_self()) {
			if (memcpy_s(address, size, buffer, size))
				throw FailedToWriteMemory();
		} else if (!NT_SUCCESS(NtWriteVirtualMemory(this->m_handle, address, buffer, size, nullptr)))
			throw FailedToWriteMemory();
	}

	// allocate virtual memory in the process (wrapper for VirtualAllocEx)
	uintptr_t Process::alloc_virt_mem(const size_t size, const uint32_t protection, const uint32_t type) const {
		void* address = nullptr; SIZE_T region_size = size;
		if (!NT_SUCCESS(NtAllocateVirtualMemory(this->m_handle, &address, 0, &region_size, type, protection)))
			throw FailedToAllocateVirtualMemory();
		return uintptr_t(address);
	}

	// free virtual memory in the process (wrapper for VirtualFreeEx)
	void Process::free_virt_mem(void* const address, const size_t size, const uint32_t type) const {
		void* base_address = address; SIZE_T region_size = size;
		if (!NT_SUCCESS(NtFreeVirtualMemory(this->m_handle, &base_address, &region_size, type)))
			throw FailedToFreeVirtualMemory();
	}

	// get the protection of a page of memory
	uint32_t Process::get_mem_prot(void* const address) const {
		MEMORY_BASIC_INFORMATION buffer;
		if (!NT_SUCCESS(NtQueryVirtualMemory(this->m_handle, address, MEMORY_INFORMATION_CLASS::MemoryBasicInformation, &buffer, sizeof(buffer), nullptr)))
			throw FailedToQueryMemoryProtection();
		return buffer.Protect;
	}

	// set the protection, returns the old protection
	uint32_t Process::set_mem_prot(void* address, const size_t size, const uint32_t protection) const {
		SIZE_T NumberOfBytesToProtect = size;
		if (DWORD OldAccessProtection; NT_SUCCESS(NtProtectVirtualMemory(this->m_handle, &address, &NumberOfBytesToProtect, protection, &OldAccessProtection)))
			return OldAccessProtection;
		throw FailedToSetMemoryProtection();
	}

	// wrapper over CreateRemoteThread (will wait infinitely for the thread to finish)
	void Process::create_remote_thread(void* const address, void* const argument) const {
		HANDLE thread_handle;
		if (!NT_SUCCESS(NtCreateThreadEx(&thread_handle, 0x1FFFFF, nullptr, this->m_handle, address, argument, 0, 0, 0, 0, nullptr)))
			throw FailedToCreateRemoteThread();

		WaitForSingleObject(thread_handle, INFINITE);
		CloseHandle(thread_handle);
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

	// get the name of the process (to cache it)
	std::string Process::query_name() const {
		char buffer[1024];
		if (DWORD size = sizeof(buffer); !QueryFullProcessImageName(this->m_handle, 0, buffer, &size))
			throw FailedToQueryProcessName();

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
			throw FailedToQueryProcessArchitecture();

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

		DWORD size = 0;
		HMODULE modules[1024];

		// get all loaded modules
		if (!EnumProcessModulesEx(this->m_handle, modules, sizeof(modules), &size, this->is_64bit() ? LIST_MODULES_64BIT : LIST_MODULES_32BIT))
			throw FailedToEnumModules();

		// iterate over each module
		for (size_t i = 0; i < size / sizeof(HMODULE); ++i) {
			// get the module name
			char buffer[256];
			GetModuleBaseNameA(this->m_handle, modules[i], buffer, sizeof(buffer));

			std::string name(buffer);

			// change to lowercase
			std::transform(name.begin(), name.end(), name.begin(), std::tolower);

			// add to list
			this->m_module_addresses[name] = uintptr_t(modules[i]);
		}
	}

	// the address of the 64bit peb
	uintptr_t Process::query_peb64_address() const {
		PROCESS_BASIC_INFORMATION info;
		if (!NT_SUCCESS(mango::NtQueryInformationProcess(this->m_handle, ProcessBasicInformation, &info, sizeof(info), nullptr)))
			throw FailedToQueryProcessInformation();

		if (sizeof(void*) == 8) { // host is a 64bit process
			return uintptr_t(info.PebBaseAddress);
		} else /* host is a 32bit process */ {
			return uintptr_t(info.PebBaseAddress) - 0x1000;
		}
	}

	// used by setup()
	void Process::setup_internal() {
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
	}

	// SeDebugPrivilege
	void Process::set_debug_privilege(bool value) const {
		// get a process token handle
		HANDLE token_handle = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token_handle))
			throw FailedToOpenProcessToken();

		// close handle when we're done
		ScopeGuard _guard(CloseHandle, token_handle);

		// get the privilege luid
		LUID luid;
		if (!LookupPrivilegeValue(0, SE_DEBUG_NAME, &luid))
			throw FailedToGetPrivilegeLUID();

		TOKEN_PRIVILEGES token_privileges;
		token_privileges.PrivilegeCount = 1;
		token_privileges.Privileges[0].Luid = luid;
		token_privileges.Privileges[0].Attributes = value ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

		// the goob part
		if (!AdjustTokenPrivileges(token_handle, false, &token_privileges, 0, 0, 0))
			throw FailedToSetTokenPrivilege();
	}
} // namespace mango