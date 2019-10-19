#include "../../include/epic/process.h"

#include <iostream>
#include <algorithm>
#include <Psapi.h>

#include "../../include/epic/shellcode.h"

#include "../../include/misc/windows_defs.h"
#include "../../include/misc/error_codes.h"
#include "../../include/misc/logger.h"


namespace mango {
	void Process::setup(const uint32_t pid) {
		this->release();

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

		this->m_pid = pid;
		this->m_is_self = (pid == GetCurrentProcessId());

		// so we don't leak a handle
		try {
			// cache some info
			this->m_process_name = this->query_name();
			this->m_is_64bit = this->query_is_64bit();

			// update the internal list of modules
			this->update_modules();
		} catch (...) {
			this->release();
			throw;
		}
	}
	void Process::release() noexcept {
		if (!this->m_is_valid)
			return;

		CloseHandle(this->m_handle);
		this->m_is_valid = false;
	}

	// caching
	bool Process::query_is_64bit() const {
		// 32bit process on 64bit os
		if (BOOL is_wow64 = false; IsWow64Process(this->m_handle, &is_wow64)) {
			if (is_wow64)
				return false;
		} else
			throw FailedToQueryProcessArchitecture();

		SYSTEM_INFO system_info;
		GetNativeSystemInfo(&system_info);
		return system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
	}
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

	std::optional<PEB> Process::get_peb() const {
		static const auto NtQueryInformationProcess = NtQueryInformationProcessFn(
			GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess"));

		// get address of the peb structure
		PROCESS_BASIC_INFORMATION process_info;
		if (DWORD tmp = 0; NtQueryInformationProcess(this->m_handle, ProcessBasicInformation, &process_info, sizeof(process_info), &tmp))
			throw FailedToQueryProcessInformation();

		return this->read<PEB>(process_info.PebBaseAddress);
	}
	const Process::Module* Process::get_module(std::string name) const noexcept {
		// special case (similar to GetModuleHandle(nullptr))
		if (name.empty())
			return &this->m_process_module;

		// change to lowercase
		std::transform(name.begin(), name.end(), name.begin(), std::tolower);

		// find the module
		if (const auto it = this->m_modules.find(name); it != this->m_modules.end())
			return &it->second;

		return nullptr;
	}
	uintptr_t Process::get_module_addr(const std::string& module_name) const noexcept {
		if (const auto mod = this->get_module(module_name); mod)
			return mod->get_image_base();
		return 0;
	}

	void Process::read(const void* const address, void* const buffer, const size_t size) const {
		if (this->is_self()) {
			if (memcpy_s(buffer, size, address, size))
				throw FailedToReadMemory();
		}
		else {
			if (!ReadProcessMemory(this->m_handle, address, buffer, size, nullptr))
				throw FailedToReadMemory();
		}
	}
	void Process::write(void* const address, const void* const buffer, const size_t size) const {
		if (this->is_self()) {
			if (memcpy_s(address, size, buffer, size))
				throw FailedToWriteMemory();
		}
		else {
			if (!WriteProcessMemory(this->m_handle, address, buffer, size, nullptr))
				throw FailedToWriteMemory();
		}
	}

	void* Process::alloc_virt_mem(const size_t size, const uint32_t protection, const uint32_t type) const {
		if (const auto ret = VirtualAllocEx(this->m_handle, nullptr, size, type, protection); ret)
			return ret;

		throw FailedToAllocateVirtualMemory();
	}
	void Process::free_virt_mem(void* const address, const size_t size, const uint32_t type) const {
		if (!VirtualFreeEx(this->m_handle, address, size, type))
			throw FailedToFreeVirtualMemory();
	}

	uint32_t Process::get_mem_prot(const void* const address) const {
		if (MEMORY_BASIC_INFORMATION mbi; VirtualQueryEx(this->m_handle, address, &mbi, sizeof(mbi)))
			return mbi.Protect;

		throw FailedToQueryMemoryProtection();
	}
	uint32_t Process::set_mem_prot(void* const address, const size_t size, const uint32_t protection) const {
		if (DWORD old_protection = 0; VirtualProtectEx(this->m_handle, address, size, protection, &old_protection))
			return old_protection;

		throw FailedToSetMemoryProtection();
	}

	uintptr_t Process::get_proc_addr(const std::string& module_name, const std::string& func_name) const {
		const auto mod = this->get_module(module_name);
		if (!mod)
			return 0;

		const auto exp = mod->get_export(func_name);
		if (!exp)
			return 0;

		return exp->m_address;
	}
	uintptr_t Process::get_proc_addr(const uintptr_t hmodule, const std::string& func_name) const {
		const auto func_addr = this->get_proc_addr("kernel32.dll", "GetProcAddress");
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

	void Process::create_remote_thread(const void* const address) const {
		const auto thread = CreateRemoteThread(this->m_handle, nullptr, 0,
			LPTHREAD_START_ROUTINE(address), nullptr, 0, 0);
		if (!thread)
			throw FailedToCreateRemoteThread();

		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
	}

	void Process::update_modules() {
		this->m_modules.clear();

		HMODULE modules[1024];

		// enumerate all loaded modules
		if (DWORD size = 0; EnumProcessModulesEx(this->m_handle, modules, sizeof(modules), &size, LIST_MODULES_ALL)) {
			// iterate over each module
			for (size_t i = 0; i < size / sizeof(HMODULE); ++i) {
				char buffer[256];
				GetModuleBaseNameA(this->m_handle, modules[i], buffer, sizeof(buffer));
				
				std::string name(buffer);

				// change to lowercase
				std::transform(name.begin(), name.end(), name.begin(), std::tolower);

				// add to list
				this->m_modules[name] = PeHeader(*this, modules[i]);
			}

			// cache the process' module
			std::string name(this->get_name());

			// change to lowercase
			std::transform(name.begin(), name.end(), name.begin(), std::tolower);

			// this process' module
			this->m_process_module = this->m_modules.at(name);
		} else
			throw FailedToUpdateModules();
	}

	// find a signature
	uintptr_t Process::find_signature(const std::string& module_name, const std::string_view& pattern) const {
		const auto parse_byte = [](const char c1, const char c2) {
			uint8_t b = 0;
			if (c1 >= '0' && c1 <= '9')
				b += uint8_t((c1 - '0') * 16);
			else
				b += uint8_t((10 + (c1 - 'A')) * 16);

			if (c2 >= '0' && c2 <= '9')
				b += uint8_t(c2 - '0');
			else
				b += uint8_t(10 + (c2 - 'A'));
			return b;
		};

		const auto mod = this->get_module(module_name);
		if (!mod)
			return 0;

		// from the start of the module memory to the end
		const auto start = mod->get_image_base(),
			end = start + mod->get_image_size();

		// read
		const auto buffer = new uint8_t[end - start];
		this->read(start, buffer, end - start);

		// check for matching sequence
		for (uintptr_t current = start; current < (end - pattern.size()); current += 1) {
			size_t j = 0;
			bool pattern_matches = true;
			for (size_t i = 0; i < pattern.size(); ++i) {
				// wildcard
				if (pattern[i] == ' ')
					continue;

				j += 1;
				if (pattern[i] == '?')
					continue;

				// check if byte matches
				if (buffer[(current - start) + j - 1] == parse_byte(std::toupper(pattern[i]), std::toupper(pattern[i + 1]))) {
					i += 1;
					continue;
				}

				pattern_matches = false;
				break;
			}

			// found pattern
			if (pattern_matches) {
				delete[] buffer;
				return current;
			}
		}

		delete[] buffer;
		return 0;
	}
} // namespace mango