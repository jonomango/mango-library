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

	template <typename Ptr>
	struct _PEB_INTERNAL {
		union {
			Ptr _alignment;
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
} // namespace mango