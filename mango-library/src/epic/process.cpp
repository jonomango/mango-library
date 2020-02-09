#include "../../include/epic/process.h"

#include <iostream>
#include <algorithm>
#include <Psapi.h>
#include <WtsApi32.h>
#include <TlHelp32.h>

#include "../../include/epic/shellcode.h"

#include "../../include/misc/scope_guard.h"
#include "../../include/misc/logger.h"


namespace mango {
	namespace impl {
		// iterate over every module in the process
		template <typename Ptr, typename Callable>
		void iterate_modules(const Process& process, Callable&& callback) {
			const auto peb = process.get_peb<Ptr>();

			// PEB_LDR_DATA
			const auto list_head = process.read<windows::PEB_LDR_DATA<Ptr>>(peb.Ldr).InMemoryOrderModuleList;
			for (auto current = list_head.Flink; current && current != list_head.Blink;) {
				// LDR_DATA_TABLE_ENTRY
				const auto table_addr = current - offsetof(windows::LDR_DATA_TABLE_ENTRY<Ptr>, InMemoryOrderLinks);
				if (!table_addr)
					break;

				const auto table_entry = process.read<windows::LDR_DATA_TABLE_ENTRY<Ptr>>(table_addr);

				const auto name_addr{ uintptr_t(table_entry.FullDllName.Buffer) };
				if (!name_addr)
					break;

				const auto name_size{ size_t(table_entry.FullDllName.Length) };

				// read the dll name
				const auto name_wstr{ std::make_unique<wchar_t[]>(name_size + 1) };
				process.read(name_addr, name_wstr.get(), name_size);
				name_wstr[name_size] = L'\0';

				// call our callback
				std::invoke(callback, wstr_to_str(name_wstr.get()), table_entry.DllBase);

				// proceed to next entry
				current = process.read<windows::LIST_ENTRY<Ptr>>(current).Flink;
			}
		}
	} // namespace impl

	// SeDebugPrivilege
	void Process::set_debug_privilege(const bool value) {
		// get a process token handle
		HANDLE token_handle{ nullptr };
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token_handle))
			throw FailedToOpenProcessToken{ mango_format_w32status(GetLastError()) };

		// close handle when we're done
		const ScopeGuard _guard{ &CloseHandle, token_handle };

		// get the privilege luid
		LUID luid{};
		if (!LookupPrivilegeValueA(0, enc_str("SeDebugPrivilege").c_str(), &luid))
			throw FailedToGetPrivilegeLUID{ mango_format_w32status(GetLastError()) };

		TOKEN_PRIVILEGES privileges{
			.PrivilegeCount = 1,
			.Privileges = { {
				.Luid = luid, 
				.Attributes = DWORD(value ? SE_PRIVILEGE_ENABLED : 0)
			} }
		};

		// the goob part
		if (!AdjustTokenPrivileges(token_handle, false, &privileges, 0, 0, 0))
			throw FailedToSetTokenPrivilege{ mango_format_w32status(GetLastError()) };
	}

	// get a list of pids that match the process name
	std::vector<uint32_t> Process::get_pids_by_name(const std::string_view process_name) {
		PWTS_PROCESS_INFOA processes{ nullptr }; DWORD count{ 0 };
		if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &processes, &count))
			throw FailedToEnumProcesses{ mango_format_w32status(GetLastError()) };

		std::vector<uint32_t> pids{};
		for (size_t i = 0; i < count; ++i) {
			if (process_name != processes[i].pProcessName)
				continue;

			pids.push_back(processes[i].ProcessId);
		}

		WTSFreeMemory(processes);
		return pids;
	}

	// setup by pid
	void Process::setup(const uint32_t pid, const SetupOptions& options) {
		this->release();

		// set debug privileges
		Process::set_debug_privilege(true);
		const ScopeGuard _guard{ &Process::set_debug_privilege, false };

		// parameters for NtOpenProcess()
#pragma warning(suppress: 4312) // conversion from 'const uint32_t' to 'PVOID' of greater size
		CLIENT_ID clientid{ PVOID(pid) };
		OBJECT_ATTRIBUTES object_attributes{ sizeof(object_attributes) };

		// open a handle to the process
		const auto status{ windows::NtOpenProcess(&this->m_handle, options.handle_access, &object_attributes, &clientid) };
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
		// never throw in a destructor
		if (this->m_is_valid) try {
			this->m_is_valid = false;
			if (this->m_free_handle)
				CloseHandle(this->m_handle);
		} catch (...) {}
	}

	// get all running thread ids
	Process::ProcessThreadIds Process::get_threadids() const {
		// TODO: find a better alternative
		const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			throw FailedToCreateThreadSnapshot(mango_format_w32status(GetLastError()));

		// get the first thread
		THREADENTRY32 entry{ .dwSize = sizeof(THREADENTRY32) };
		if (!Thread32First(snapshot, &entry))
			throw FailedToGetFirstThread(mango_format_w32status(GetLastError()));

		ProcessThreadIds threads;

		// iterate through the rest of the threads
		do {
			if (entry.th32OwnerProcessID == this->m_pid)
				threads.push_back(entry.th32ThreadID);
		} while (Thread32Next(snapshot, &entry));

		return threads;
	}

	// get a loaded module, case-insensitive (passing "" for name returns the current process module)
	const LoadedModule* Process::get_module(const std::string_view name) const {
		std::string search_name{ name };

		if (name.empty()) /* return own module */ {
			search_name = this->get_name();
		} else {
			// check if its in the apiset
			try {
				search_name = this->resolve_apiset(name);
			} catch (ApiSetInvalidName&) {}
		}

		str_tolower(search_name);

		// find the module
		if (const auto it{ this->m_modules.find(search_name) }; it != this->m_modules.end())
			return &it->second;
		
		// module might not be loaded yet (defer loading option)
		if (this->m_options.defer_module_loading) {
			if (const auto it{ this->m_module_addresses.find(search_name) }; it != this->m_module_addresses.end())
				return &(this->m_modules[it->first] = LoadedModule{ *this, it->second });
		}

		// module not found
		return nullptr;
	}

	// get the base address of a module
	uintptr_t Process::get_module_addr(const std::string_view module_name) const {
		if (const auto mod{ this->get_module(module_name) }; mod)
			return mod->get_image_base();
		return 0;
	}

	// this uses the internal list of modules to find the function address
	uintptr_t Process::get_proc_addr(const std::string_view module_name, const std::string_view func_name) const {
		const auto mod{ this->get_module(module_name) };
		if (!mod)
			return 0;

		const auto exp{ mod->get_export(func_name) };
		if (!exp)
			return 0;

		return exp->address;
	}

	// api name -> dll name
	std::string Process::resolve_apiset(const std::string_view name) const {
		// my implementation of https://lucasg.github.io/2017/10/15/Api-set-resolution/

		// trim everything after the last "-" and convert to lowercase
		std::wstring search_name{};
		if (const auto index(name.find_last_of('-')); index != -1) {
			std::transform(std::begin(name), std::begin(name) + 
				index, std::back_inserter(search_name), tolower_t<wchar_t>);
		}

		// name must start with either "api-" or "ext-"
		if (search_name.size() < 4 ||
			(*reinterpret_cast<const uint64_t*>(search_name.data()) != 0x2D006900700061 &&
			 *reinterpret_cast<const uint64_t*>(search_name.data()) != 0x2D007400780065)) {
			throw ApiSetInvalidName(enc_str("Name = "), '"', name, '"');
		}

		// api set map addr is stored in the PEB
		const auto api_set_map_addr(this->is_64bit() ? 
			uintptr_t(this->get_peb<uint64_t>().ApiSetMap) : 
			uintptr_t(this->get_peb<uint32_t>().ApiSetMap));

		const auto api_set_map(this->read<windows::API_SET_NAMESPACE>(api_set_map_addr));

		// read every entry at once for optimization
		const auto entries(std::make_unique<windows::API_SET_NAMESPACE_ENTRY[]>(api_set_map.Count));
		this->read(api_set_map_addr + api_set_map.EntryOffset, entries.get(), api_set_map.Count * sizeof(windows::API_SET_NAMESPACE_ENTRY));

		// go through each entry
		for (size_t i(0); i < api_set_map.Count; ++i) {
			const auto& entry(entries[i]);

			// no values, pointless to check
			if (entry.ValueCount <= 0)
				continue;

			// read the name
			// TODO: somehow reduce read calls here?
			std::wstring entry_name(entry.NameLength / 2, L' ');
			this->read(api_set_map_addr + entry.NameOffset, entry_name.data(), entry.NameLength);

			// NOTE:
			// im assumming here that all name entries are always in lowercase...
			// this could break if this stops being the case later on

			// is this what we're looking for?
			if (entry_name.compare(0, search_name.size(), search_name) == 0) {
				const auto value(this->read<windows::API_SET_VALUE_ENTRY>(api_set_map_addr + entry.ValueOffset));
				
				// read the value name
				std::wstring resolved_name(value.ValueLength / 2, L' ');
				this->read(api_set_map_addr + value.ValueOffset, resolved_name.data(), value.ValueLength);

				// TODO: should probably change everything to be using wstrings eventually...
				return wstr_to_str(resolved_name);
			}
		}

		// rip
		throw FailedToResolveApiSetName(enc_str("Name = "), '"', name, '"');
	}

	// get the protection of a page of memory
	uint32_t Process::get_mem_prot(void* const address) const {
		MEMORY_BASIC_INFORMATION buffer{};
		if (const auto status{ windows::NtQueryVirtualMemory(this->m_handle, address,
			windows::MemoryBasicInformation, &buffer, sizeof(buffer), nullptr) }; NT_ERROR(status)) 
		{
			throw FailedToQueryMemoryProtection{ mango_format_ntstatus(status) };
		}
		return buffer.Protect;
	}

	// set the protection, returns the old protection
	uint32_t Process::set_mem_prot(void* address, const size_t size, const uint32_t protection) const {
		DWORD OldAccessProtection{ 0 }; SIZE_T NumberOfBytesToProtect{ size };
		if (const auto status{ windows::NtProtectVirtualMemory(this->m_handle, &address,
			&NumberOfBytesToProtect, protection, &OldAccessProtection) }; NT_ERROR(status)) 
		{
			throw FailedToSetMemoryProtection{ mango_format_ntstatus(status) };
		}
		return OldAccessProtection;
	}

	// suspend/resume the process
	void Process::suspend() const {
		if (const auto status{ windows::NtSuspendProcess(this->m_handle) }; NT_ERROR(status))
			throw FailedToSuspendProcess{ mango_format_ntstatus(status) };
	}
	void Process::resume() const {
		if (const auto status{ windows::NtResumeProcess(this->m_handle) }; NT_ERROR(status))
			throw FailedToResumeProcess{ mango_format_ntstatus(status) };
	}

	// get the handles that the process currently has open
	Process::ProcessHandles Process::get_open_handles() const {
		unsigned long buffer_size{ 0xFFFF };
		uint8_t* buffer{ new uint8_t[buffer_size] };

		// make sure we delete the fat chunk of memory
		const ScopeGuard _guard{ [&]() { delete[] buffer; } };

		// query system info
		NTSTATUS status{ 0 };
		while (0xC0000004 == (status = windows::NtQuerySystemInformation(
			windows::SystemHandleInformation, buffer, buffer_size, nullptr))) 
		{
			// STATUS_INFO_LENGTH_MISMATCH
			// buffer too small, allocate larger
			delete[] buffer; buffer = new uint8_t[buffer_size *= 2];
		}

		// failure
		if (NT_ERROR(status))
			throw FailedToQuerySystemInformation{ mango_format_ntstatus(status) };

		std::vector<HandleInfo> handles{};

		// filter out handles to the process
		const auto handle_info = reinterpret_cast<windows::SYSTEM_HANDLE_INFORMATION*>(buffer);
		for (size_t i{ 0 }; i < handle_info->HandleCount; ++i) {
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
			this->m_modules[name] = LoadedModule{ *this, address };
	}

	// get the name of the process (to cache it)
	std::string Process::query_name() const {
		char buffer[1024];
		if (DWORD size{ sizeof(buffer) }; !QueryFullProcessImageName(this->m_handle, 0, buffer, &size))
			throw FailedToQueryProcessName{ mango_format_w32status(GetLastError()) };

		std::string name{ buffer };

		// erase everything before the last back slash
		const size_t pos{ name.find_last_of('\\') };
		if (pos != std::string::npos)
			name = name.substr(pos + 1);

		return name;
	}

	// wow64 process
	bool Process::query_is_wow64() const {
		// check if Wow64 is present
		BOOL is_wow64{ false };
		if (!IsWow64Process(this->m_handle, &is_wow64))
			throw FailedToQueryProcessArchitecture{ mango_format_w32status(GetLastError()) };

		return is_wow64;
	}

	// check whether the process is 64bit or not (to cache it)
	bool Process::query_is_64bit() const {
		// 32bit process on 64bit os
		if (this->m_is_wow64)
			return false;

		SYSTEM_INFO system_info{};
		GetNativeSystemInfo(&system_info);
		return system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
	}

	// update the internal list of module addresses
	void Process::query_module_addresses() {
		// clear any previous module addresses
		this->m_module_addresses.clear();

		const auto callback{ [&](auto name, const auto base) {
			// remove everything before the filename
			if (const auto index{ name.find_last_of('\\') }; index != std::string::npos)
				name.erase(name.begin(), name.begin() + index + 1);

			// if it's an apiset name
			try {
				name = this->resolve_apiset(name);
			} catch (ApiSetInvalidName&) {}

			str_tolower(name);
			this->m_module_addresses[name] = uintptr_t(base);
		} };

		if (this->is_64bit()) {
			impl::iterate_modules<uint64_t>(*this, callback);
		} else {
			impl::iterate_modules<uint32_t>(*this, callback);
		}
	}

	// the address of the 64bit peb
	uintptr_t Process::query_peb64_address() const {
		PROCESS_BASIC_INFORMATION info{};
		if (const auto status{ windows::NtQueryInformationProcess(this->m_handle,
			ProcessBasicInformation, &info, sizeof(info), nullptr) }; NT_ERROR(status)) 
		{
			throw FailedToQueryProcessInformation{ mango_format_ntstatus(status) };
		}

		if constexpr (sizeof(void*) == 8) { // host is a 64bit process
			return uintptr_t(info.PebBaseAddress);
		} else /* host is a 32bit process */ {
			return uintptr_t(info.PebBaseAddress) - 0x1000;
		}
	}

	// used by setup()
	void Process::setup_internal() {
		// properly cleanup if an exception is thrown
		ScopeGuard _guard{ &Process::release, this };

		this->m_is_valid = true;
		this->m_pid = GetProcessId(this->m_handle);
		this->m_is_self = (this->m_pid == GetCurrentProcessId());

		// cache some info
		this->m_is_wow64 = this->query_is_wow64();
		this->m_is_64bit = this->query_is_64bit();

		// access a 64bit program from a 32bit program
		if constexpr (sizeof(void*) == 4) {
			if (this->m_is_64bit)
				throw CantSetup64From32();
		}

		this->m_process_name = this->query_name();
		this->m_peb64_address = this->query_peb64_address();

		// update the internal list of modules
		if (!this->m_options.defer_module_loading) {
			this->load_modules();
		} else {
			this->query_module_addresses();
		}

		// no exception was thrown, great
		_guard.cancel();
	}

	// override to change internal behavior
	void Process::default_read_memory_func(const Process* const process, const void* const address, void* const buffer, const size_t size) {
		if (process->is_self()) {
			if (memcpy_s(buffer, size, address, size))
				throw FailedToReadMemory{};
		} else if (const auto status{ windows::NtReadVirtualMemory(
			process->get_handle(), address, buffer, size, nullptr) }; NT_ERROR(status)) 
		{
			throw FailedToReadMemory{ mango_format_ntstatus(status) };
		}
	}
	void Process::default_write_memory_func(const Process* const process, void* const address, const void* const buffer, const size_t size) {
		if (process->is_self()) {
			if (memcpy_s(address, size, buffer, size))
				throw FailedToWriteMemory{};
		} else if (const auto status{ windows::NtWriteVirtualMemory(
			process->get_handle(), address, buffer, size, nullptr) }; NT_ERROR(status)) 
		{
			throw FailedToWriteMemory{ mango_format_ntstatus(status) };
		}
	}
	void* Process::default_allocate_memory_func(const Process* const process, const size_t size, const uint32_t protection, const uint32_t type) {
		void* address{ nullptr }; SIZE_T region_size{ size };
		if (const auto status{ windows::NtAllocateVirtualMemory(process->get_handle(),
			&address, 0, &region_size, type, protection) }; NT_ERROR(status)) 
		{
			throw FailedToAllocateVirtualMemory{ mango_format_ntstatus(status) };
		}
		return address;
	}
	void Process::default_free_memory_func(const Process* const process, void* const address, const size_t size, const uint32_t type) {
		void* base_address{ address }; SIZE_T region_size{ size };
		if (const auto status{ windows::NtFreeVirtualMemory(process->get_handle(),
			&base_address, &region_size, type) }; NT_ERROR(status)) 
		{
			throw FailedToFreeVirtualMemory{ mango_format_ntstatus(status) };
		}
	}
	void Process::default_create_remote_thread_func(const Process* const process, void* const address, void* const argument) {
		HANDLE thread_handle{};
		if (const auto status{ windows::NtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS, nullptr,
			process->get_handle(), address, argument, 0, 0, 0, 0, nullptr) }; NT_ERROR(status)) 
		{
			throw FailedToCreateRemoteThread{ mango_format_ntstatus(status) };
		}

		WaitForSingleObject(thread_handle, INFINITE);
		CloseHandle(thread_handle);
	}
} // namespace mango