#pragma once

#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdint.h>


namespace mango::windows {
	enum MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation
	};

	// ApiSet structs are taken from https://lucasg.github.io/2017/10/15/Api-set-resolution/
	struct API_SET_NAMESPACE {
		ULONG Version;     // v2 on Windows 7, v4 on Windows 8.1  and v6 on Windows 10
		ULONG Size;        // apiset map size (usually the .apiset section virtual size)
		ULONG Flags;       // according to Geoff Chappell,  tells if the map is sealed or not.
		ULONG Count;       // hash table entry count
		ULONG EntryOffset; // Offset to the api set entries values
		ULONG HashOffset;  // Offset to the api set entries hash indexes
		ULONG HashFactor;  // multiplier to use when computing hash 
	};

	// Hash table value
	struct API_SET_NAMESPACE_ENTRY {
		ULONG Flags;        // sealed flag in bit 0
		ULONG NameOffset;   // Offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
		ULONG NameLength;   // Ignored
		ULONG HashedLength; // Apiset library name length
		ULONG ValueOffset;  // Offset the list of hosts library implement the apiset contract (points to API_SET_VALUE_ENTRY array)
		ULONG ValueCount;   // Number of hosts libraries 
	};

	// Host Library entry
	struct API_SET_VALUE_ENTRY {
		ULONG Flags;        // sealed flag in bit 0
		ULONG NameOffset;   // Offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
		ULONG NameLength;   // Apiset library name length
		ULONG ValueOffset;  // Offset to the Host library name PWCHAR (e.g. "ucrtbase.dll")
		ULONG ValueLength;  // Host library name length
	};

	struct INITIAL_TEB {
		void* StackBase;
		void* StackLimit;
		void* StackCommit;
		void* StackCommitMax;
		void* StackReserved;
	};

	template <typename Ptr>
	struct UNICODE_STRING {
		uint16_t Length;
		uint16_t MaximumLength;
		Ptr Buffer;
	};

	using UNICODE_STRING32 = UNICODE_STRING<uint32_t>;
	using UNICODE_STRING64 = UNICODE_STRING<uint64_t>;

	template <typename Ptr>
	struct LIST_ENTRY {
		Ptr Flink;
		Ptr Blink;
	};

	using LIST_ENTRY32 = LIST_ENTRY<uint32_t>;
	using LIST_ENTRY64 = LIST_ENTRY<uint64_t>;

	template <typename Ptr>
	struct PEB_LDR_DATA {
	private:
		uint8_t _padding_1[8];
		Ptr _padding_2[3];
	public:
		LIST_ENTRY<Ptr> InMemoryOrderModuleList;
	};

	using PEB_LDR_DATA32 = PEB_LDR_DATA<uint32_t>;
	using PEB_LDR_DATA64 = PEB_LDR_DATA<uint64_t>;

	template <typename Ptr>
	struct LDR_DATA_TABLE_ENTRY {
	private:
		Ptr _padding_1[2];
	public:
		LIST_ENTRY<Ptr> InMemoryOrderLinks;
	private:
		Ptr _padding_2[2];
	public:
		Ptr DllBase;
	private:
		Ptr _padding_3[2];
	public:
		UNICODE_STRING<Ptr> FullDllName;
	private:
		uint8_t _padding_4[8];
		Ptr _padding_5[3];
	public:
		union {
			uint32_t CheckSum;
			Ptr _padding_6;
		};

		uint32_t TimeDateStamp;
	};

	using LDR_DATA_TABLE_ENTRY32 = LDR_DATA_TABLE_ENTRY<uint32_t>;
	using LDR_DATA_TABLE_ENTRY64 = LDR_DATA_TABLE_ENTRY<uint64_t>;

	// http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
#pragma warning(push)
#pragma warning(disable : 4201) // warning C4201: nonstandard extension used: nameless struct/union
	template <typename Ptr>
	struct PEB {
		union {
			Ptr _alignment1;
			struct {
				uint8_t InheritedAddressSpace;
				uint8_t ReadImageFileExecOptions;
				uint8_t BeingDebugged;
				uint8_t BitField;
			};
		};

		Ptr Mutant;
		Ptr ImageBaseAddress;
		Ptr Ldr;

	private:
		Ptr	    _padding1[0x6];

	public:
		union {
			Ptr _alignment2;
			unsigned long CrossProcessFlags;
			struct {
				unsigned long ProcessInJob : 1,
					ProcessInitializing : 1,
					ProcessUsingVEH : 1,
					ProcessUsingVCH : 1,
					ProcessUsingFTH : 1;
			};
		};

	private:
		Ptr _padding2[0x1];
		uint8_t _padding3[0x8];

	public:
		Ptr ApiSetMap;

		union {
			Ptr _alignment3;
			unsigned long TlsExpansionCounter;
		};

	public:
		Ptr TlsBitmap;
		unsigned long TlsBitmapBits[2];
	};
#pragma warning(pop)

	using PEB32 = PEB<uint32_t>;
	using PEB64 = PEB<uint64_t>;

	struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
		DWORD ProcessId;
		BYTE ObjectTypeNumber;
		BYTE Flags;
		WORD Handle;
		PVOID ObjectAddress;
		ACCESS_MASK GrantedAccess;
	};

	struct SYSTEM_HANDLE_INFORMATION {
		DWORD HandleCount;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
	};

	static constexpr auto SystemHandleInformation = SYSTEM_INFORMATION_CLASS(16);

	// implemented as direct syscalls
	NTSTATUS NtReadVirtualMemory(HANDLE hProcess, LPCVOID lpBaseAddress, 
		LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

	NTSTATUS NtWriteVirtualMemory(HANDLE hProcess, LPVOID lpBaseAddress, 
		LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

	NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, 
		ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

	NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, 
		PSIZE_T RegionSize, ULONG FreeType);

	NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, 
		MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, 
		SIZE_T Length, PSIZE_T ResultLength);

	NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, 
		PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

	NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, 
		PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartAddress,
		PVOID Parameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, 
		SIZE_T SizeOfStackReserve, PVOID BytesBuffer);

	NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, 
		PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

	NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);

	NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, 
		PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	NTSTATUS NtSuspendProcess(HANDLE ProcessHandle);

	NTSTATUS NtResumeProcess(HANDLE ProcessHandle);
} // namespace mango::windows