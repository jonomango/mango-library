#include "../../include/epic/process.h"

#include <iostream>
#include <algorithm>
#include <Psapi.h>

#include "../../include/epic/shellcode.h"
#include "../../include/epic/syscalls.h"
#include "../../include/epic/windows_defs.h"

#include "../../include/misc/error_codes.h"
#include "../../include/misc/logger.h"


namespace mango {
	// initialization
	void Process::setup(const uint32_t pid, const SetupOptions& options) {
		this->release();

		// for syscalls
		if (!mango::verify_x64transition())
			throw FailedToVerifyX64Transition();

		// open a handle to the process
		this->m_handle = OpenProcess(
			PROCESS_VM_READ | // ReadProcessMemory
			PROCESS_VM_WRITE | // WriteProcessMemory
			PROCESS_VM_OPERATION | // VirtualAllocEx / VirtualProtectEx
			PROCESS_QUERY_INFORMATION | // QueryFullProcessImageName
			PROCESS_CREATE_THREAD, // CreateRemoteThread
			FALSE, pid
		);

		// whether we're valid or not depends entirely on OpenProcess()
		if (this->m_handle == nullptr)
			throw InvalidProcessHandle();

		this->m_is_valid = true;
		this->m_options = options;
		this->m_pid = pid;
		this->m_is_self = (pid == GetCurrentProcessId());

		// so we don't leak a handle
		try {
			// cache some info
			this->m_process_name = this->query_name();
			this->m_is_64bit = this->query_is_64bit();

			// update the internal list of modules
			if (!options.m_defer_module_loading)
				this->load_modules();
			else
				this->query_module_addresses();
		} catch (...) {
			this->release();
			throw;
		}
	}

	// clean up
	void Process::release() noexcept {
		if (!this->m_is_valid)
			return;

		CloseHandle(this->m_handle);
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

	// uses shellcode to call GetProcAddress() in the remote process
	uintptr_t Process::get_proc_addr(const uintptr_t hmodule, const std::string& func_name) const {
		const auto func_addr = this->get_proc_addr(enc_str("kernel32.dll"), enc_str("GetProcAddress"));
		if (!func_addr)
			throw FailedToGetFunctionAddress();

		// this will store func_name
		const auto str_address = uintptr_t(this->alloc_virt_mem(func_name.size() + 1));

		// for the return value of GetProcAddress
		const auto ret_address = uintptr_t(this->alloc_virt_mem(this->get_ptr_size()));

		// copy the func_name
		this->write(str_address, func_name.data(), func_name.size() + 1);

		// the return value of GetProcAddress()
		uintptr_t ret_value = 0;

		if (this->is_64bit()) {
			Shellcode(
				"\x48\x83\xEC\x20", // sub rsp, 0x20
				"\x48\xBA", str_address, // movabs rdx, str_address
				"\x48\xB9", hmodule, // movabs rcx, hmodule
				"\x48\xB8", func_addr, // movabs rax, func_addr
				"\xFF\xD0", // call rax
				"\x48\xA3", ret_address, // movabs [ret_address], rax
				"\x48\x83\xC4\x20", // add rsp, 0x20
				"\xC3" // ret
			).execute(*this);

			ret_value = uintptr_t(this->read<uint64_t>(ret_address));
		} else {
			Shellcode(
				"\x68", uint32_t(str_address), // push str_address
				"\x68", uint32_t(hmodule), // push hmodule
				"\xB8", uint32_t(func_addr), // mov eax, func_addr
				"\xFF\xD0", // call eax
				"\xA3", uint32_t(ret_address), // mov [ret_address], eax
				"\xC3" // ret
			).execute(*this);

			ret_value = this->read<uint32_t>(ret_address);
		}

		// free memory
		this->free_virt_mem(str_address);
		this->free_virt_mem(ret_address);

		return ret_value;
	}

	// read from a memory address
	void Process::read(const void* const address, void* const buffer, const size_t size) const {
		if (this->is_self()) {
			if (memcpy_s(buffer, size, address, size))
				throw FailedToReadMemory();
		} else if (!NT_SUCCESS(NtReadVirtualMemory(this->m_handle, address, buffer, size, nullptr)))
			throw FailedToReadMemory();
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
	void Process::create_remote_thread(void* const address) const {
		HANDLE thread_handle;
		if (!NT_SUCCESS(NtCreateThreadEx(&thread_handle, 0x1FFFFF, nullptr, this->m_handle, address, nullptr, 0, 0, 0, 0, nullptr)))
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

	// check whether the process is 64bit or not (to cache it)
	bool Process::query_is_64bit() const {
		// check if Wow64 is present
		BOOL is_wow64 = false;
		if (!IsWow64Process(this->m_handle, &is_wow64))
			throw FailedToQueryProcessArchitecture();

		// 32bit process on 64bit os
		if (is_wow64)
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
} // namespace mango