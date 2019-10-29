#include "../../include/epic/windows_funcs.h"

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
} // namespace mango