#include <epic/process.h>

#include <iostream>
#include <Psapi.h>


namespace mango {
	Process::Process() : Process(GetCurrentProcessId()) { 
		this->m_is_self = true; 
	}
	Process::Process(const uint32_t pid) : m_pid(pid) {
		this->m_handle = OpenProcess(
			PROCESS_VM_READ | // ReadProcessMemory
			PROCESS_VM_WRITE | // WriteProcessMemory
			PROCESS_VM_OPERATION | // VirtualAllocEx / VirtualProtectEx
			PROCESS_QUERY_LIMITED_INFORMATION, // QueryFullProcessImageName
			FALSE, pid
		);

		// whether we're valid or not depends entirely on OpenProcess()
		this->m_is_valid = (this->m_handle != nullptr);
		if (!this->is_valid())
			return;

		// update the internal list of modules
		this->update_modules();

		// cache the process name
		this->m_process_name = this->query_name();

		// cache the process' module
		if (const auto it = this->m_modules.find(this->get_name()); it != this->m_modules.end())
			this->m_process_module = it->second;
	}
	Process::~Process() {
		if (!this->m_is_valid)
			return;

		CloseHandle(this->m_handle);
		this->m_is_valid = false;
	}

	bool Process::is_64bit() const {
		// 32bit process on 64bit os
		if (BOOL is_wow64 = false; !IsWow64Process(this->m_handle, &is_wow64) || is_wow64)
			return false;

		SYSTEM_INFO system_info;
		GetNativeSystemInfo(&system_info);
		return system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
	}

	std::string Process::query_name() const {
		char buffer[1024];
		if (DWORD size = sizeof(buffer); !QueryFullProcessImageName(this->m_handle, 0, buffer, &size))
			return "";

		std::string name(buffer);

		// erase everything before the last back slash
		const size_t pos = name.find_last_of('\\');
		if (pos != std::string::npos)
			name = name.substr(pos + 1);

		return name;
	}
	std::optional<PEB> Process::get_peb() const {
		using NtQueryInformationProcessFn = NTSTATUS(__stdcall*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
		static const auto NtQueryInformationProcess = NtQueryInformationProcessFn(
			GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

		if (!NtQueryInformationProcess)
			return {};

		// get address of the peb structure
		PROCESS_BASIC_INFORMATION process_info;
		if (DWORD tmp = 0; NtQueryInformationProcess(this->m_handle, ProcessBasicInformation, &process_info, sizeof(process_info), &tmp))
			return {};

		return this->read<PEB>(process_info.PebBaseAddress);
	}
	std::optional<Process::Module> Process::get_module(const std::string& name) const {
		// special case (similar to GetModuleHandle(nullptr))
		if (name.empty())
			return this->m_process_module;

		// find the module
		if (const auto it = this->m_modules.find(name); it != this->m_modules.end())
			return it->second;
		return {};
	}

	void Process::read(const void* const address, void* const buffer, const size_t size) const {
		if (this->is_self())
			memcpy_s(buffer, size, address, size);
		else
			ReadProcessMemory(this->m_handle, address, buffer, size, nullptr);
	}
	void Process::write(void* const address, const void* const buffer, const size_t size) const {
		if (this->is_self())
			memcpy_s(address, size, buffer, size);
		else
			WriteProcessMemory(this->m_handle, address, buffer, size, nullptr);
	}

	void* Process::alloc_virt_mem(const size_t size, const uint32_t protection, const uint32_t type) const {
		return VirtualAllocEx(this->m_handle, nullptr, size, type, protection);
	}
	void Process::free_virt_mem(void* const address, const size_t size, const uint32_t type) const {
		VirtualFreeEx(this->m_handle, address, size, type);
	}

	uint32_t Process::get_mem_prot(const void* const address) const {
		if (MEMORY_BASIC_INFORMATION mbi; VirtualQueryEx(this->m_handle, address, &mbi, sizeof(mbi)))
			return mbi.Protect;
		return 0;
	}
	uint32_t Process::set_mem_prot(void* const address, const size_t size, const uint32_t protection) const {
		if (DWORD old_protection = 0; VirtualProtectEx(this->m_handle, address, size, protection, &old_protection))
			return old_protection;
		return 0;
	}

	void Process::update_modules() {
		this->m_modules.clear();

		HMODULE modules[1024];

		// enumerate all loaded modules
		if (DWORD size = 0; EnumProcessModules(this->m_handle, modules, sizeof(modules), &size)) {
			// iterate over each module
			for (size_t i = 0; i < size / sizeof(HMODULE); ++i) {
				char name[256];
				GetModuleBaseName(this->m_handle, modules[i], name, sizeof(name));
				
				// add to list
				this->m_modules[name] = { uintptr_t(modules[i]) };
			}
		} else {
			std::cout << "Failed to fetch modules." << std::endl;
		}
	}
} // namespace mango