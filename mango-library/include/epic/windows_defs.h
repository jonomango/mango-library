#pragma once

#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdint.h>


namespace mango {
	enum MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation
	};
	typedef struct _CLIENT_ID {
		void* UniqueProcess;
		void* UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	// ApiSet stuff is taken from https://lucasg.github.io/2017/10/15/Api-set-resolution/
	typedef struct _API_SET_NAMESPACE {
		ULONG Version;     // v2 on Windows 7, v4 on Windows 8.1  and v6 on Windows 10
		ULONG Size;        // apiset map size (usually the .apiset section virtual size)
		ULONG Flags;       // according to Geoff Chappell,  tells if the map is sealed or not.
		ULONG Count;       // hash table entry count
		ULONG EntryOffset; // Offset to the api set entries values
		ULONG HashOffset;  // Offset to the api set entries hash indexes
		ULONG HashFactor;  // multiplier to use when computing hash 
	} API_SET_NAMESPACE;

	// Hash table value
	typedef struct _API_SET_NAMESPACE_ENTRY {
		ULONG Flags;        // sealed flag in bit 0
		ULONG NameOffset;   // Offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
		ULONG NameLength;   // Ignored
		ULONG HashedLength; // Apiset library name length
		ULONG ValueOffset;  // Offset the list of hosts library implement the apiset contract (points to API_SET_VALUE_ENTRY array)
		ULONG ValueCount;   // Number of hosts libraries 
	} API_SET_NAMESPACE_ENTRY;

	// Host Library entry
	typedef struct _API_SET_VALUE_ENTRY {
		ULONG Flags;        // sealed flag in bit 0
		ULONG NameOffset;   // Offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
		ULONG NameLength;   // Apiset library name length
		ULONG ValueOffset;  // Offset to the Host library name PWCHAR (e.g. "ucrtbase.dll")
		ULONG ValueLength;  // Host library name length
	} API_SET_VALUE_ENTRY;

	typedef struct _INITIAL_TEB {
		void* StackBase;
		void* StackLimit;
		void* StackCommit;
		void* StackCommitMax;
		void* StackReserved;
	} INITIAL_TEB, *PINITIAL_TEB;

	template <typename Ptr>
	struct _UNICODE_STRING_INTERNAL {
		uint16_t Length;
		uint16_t MaximumLength;
		Ptr Buffer;
	};

	using UNICODE_STRING_M32 = _UNICODE_STRING_INTERNAL<uint32_t>;
	using UNICODE_STRING_M64 = _UNICODE_STRING_INTERNAL<uint64_t>;

	template <typename Ptr>
	struct _LIST_ENTRY_INTERNAL {
		Ptr Flink;
		Ptr Blink;
	};

	using LIST_ENTRY_M32 = _LIST_ENTRY_INTERNAL<uint32_t>;
	using LIST_ENTRY_M64 = _LIST_ENTRY_INTERNAL<uint64_t>;

	template <typename Ptr>
	struct _PEB_LDR_DATA_INTERNAL {
	private:
		uint8_t _padding_1[8];
		Ptr _padding_2[3];
	public:
		_LIST_ENTRY_INTERNAL<Ptr> InMemoryOrderModuleList;
	};

	using PEB_LDR_DATA_M32 = _PEB_LDR_DATA_INTERNAL<uint32_t>;
	using PEB_LDR_DATA_M64 = _PEB_LDR_DATA_INTERNAL<uint64_t>;

	template <typename Ptr>
	struct _LDR_DATA_TABLE_ENTRY_INTERNAL {
	private:
		Ptr _padding_1[2];
	public:
		_LIST_ENTRY_INTERNAL<Ptr> InMemoryOrderLinks;
	private:
		Ptr _padding_2[2];
	public:
		Ptr DllBase;
	private:
		Ptr _padding_3[2];
	public:
		_UNICODE_STRING_INTERNAL<Ptr> FullDllName;
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

	using LDR_DATA_TABLE_ENTRY_M32 = _LDR_DATA_TABLE_ENTRY_INTERNAL<uint32_t>;
	using LDR_DATA_TABLE_ENTRY_M64 = _LDR_DATA_TABLE_ENTRY_INTERNAL<uint64_t>;

	// http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
	template <typename Ptr>
	struct _PEB_INTERNAL {
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

	using PEB_M32 = _PEB_INTERNAL<uint32_t>;
	using PEB_M64 = _PEB_INTERNAL<uint64_t>;

	struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
		DWORD ProcessId;
		BYTE ObjectTypeNumber;
		BYTE Flags;
		WORD Handle;
		PVOID ObjectAddress;
		ACCESS_MASK GrantedAccess;
	};

	typedef struct _SYSTEM_HANDLE_INFORMATION {
		DWORD HandleCount;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
	} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

	static constexpr auto SystemHandleInformation = SYSTEM_INFORMATION_CLASS(16);

	// implemented as direct syscalls
	NTSTATUS NtReadVirtualMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
	NTSTATUS NtWriteVirtualMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
	NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
	NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
	NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, SIZE_T Length, PSIZE_T ResultLength);
	NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
	NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartAddress,
		PVOID Parameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID BytesBuffer);
	NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
		ULONG ProcessInformationLength, PULONG ReturnLength);
	NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	NTSTATUS NtSuspendProcess(HANDLE ProcessHandle);
	NTSTATUS NtResumeProcess(HANDLE ProcessHandle);
} // namespace mango