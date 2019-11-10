#pragma once

#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdint.h>


namespace mango {
	enum class MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation
	};
	typedef struct _CLIENT_ID {
		PVOID UniqueProcess;
		PVOID UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	typedef struct _INITIAL_TEB {
		PVOID StackBase;
		PVOID StackLimit;
		PVOID StackCommit;
		PVOID StackCommitMax;
		PVOID StackReserved;
	} INITIAL_TEB, *PINITIAL_TEB;

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

	using PEB32 = _PEB_INTERNAL<uint32_t>;
	using PEB64 = _PEB_INTERNAL<uint64_t>;

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
} // namespace mango