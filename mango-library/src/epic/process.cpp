#include <epic/process.h>

#include <iostream>


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

		this->m_is_valid = (this->m_handle != nullptr);
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

	std::string Process::get_name() const {
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
		if (DWORD tmp; NtQueryInformationProcess(this->m_handle, ProcessBasicInformation, &process_info, sizeof(process_info), &tmp))
			return {};

		return this->read<PEB>(process_info.PebBaseAddress);
	}
} // namespace mango