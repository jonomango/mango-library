#include "../../include/epic/windows_defs.h"

#include "../../include/epic/syscalls.h"


namespace mango {
	NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, LPCVOID BaseAddress, LPVOID Buffer, SIZE_T Size, SIZE_T* NumberOfBytesWritten) {
		static const auto index = syscall_index(enc_str("NtReadVirtualMemory"));
		return syscall<NTSTATUS>(index, ProcessHandle, BaseAddress, Buffer, Size, NumberOfBytesWritten);
	}
	NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, SIZE_T Size, SIZE_T* NumberOfBytesWritten) {
		static const auto index = syscall_index(enc_str("NtWriteVirtualMemory"));
		return syscall<NTSTATUS>(index, ProcessHandle, BaseAddress, Buffer, Size, NumberOfBytesWritten);
	}
	NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
		static const auto index = syscall_index(enc_str("NtAllocateVirtualMemory"));
		return syscall<NTSTATUS>(index, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	}
	NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
		static const auto index = syscall_index(enc_str("NtFreeVirtualMemory"));
		return syscall<NTSTATUS>(index, ProcessHandle, BaseAddress, RegionSize, FreeType);
	}
	NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, SIZE_T Length, PSIZE_T ResultLength) {
		static const auto index = syscall_index(enc_str("NtQueryVirtualMemory"));
		return syscall<NTSTATUS>(index, ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength);
	}
	NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
		static const auto index = syscall_index(enc_str("NtProtectVirtualMemory"));
		return syscall<NTSTATUS>(index, ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}
	NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartAddress,
			PVOID Parameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID BytesBuffer) {
		static const auto index = syscall_index(enc_str("NtCreateThreadEx"));
		return syscall<NTSTATUS>(index, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, 
			StartAddress, Parameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, BytesBuffer);
	}
	NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
		ULONG ProcessInformationLength, PULONG ReturnLength) {
		static const auto index = syscall_index(enc_str("NtQueryInformationProcess"));
		return syscall<NTSTATUS>(index, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	}
} // namespace mango