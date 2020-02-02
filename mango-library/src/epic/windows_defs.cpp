#include "../../include/epic/windows_defs.h"
#include "../../include/epic/syscall.h"

#include "../../include/crypto/string_encryption.h"


#define SYSCALL_WRAPPER(name, ...)\
	static const auto _syscall_index_ ## name = syscall::index(enc_str(#name));\
	return syscall::call<NTSTATUS>(_syscall_index_ ## name, __VA_ARGS__);


namespace mango::windows {
	NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, LPCVOID BaseAddress, 
		LPVOID Buffer, SIZE_T Size, SIZE_T* NumberOfBytesWritten) 
	{
		SYSCALL_WRAPPER(NtReadVirtualMemory, ProcessHandle, 
			BaseAddress, Buffer, Size, NumberOfBytesWritten)
	}
	NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, LPVOID BaseAddress, 
		LPCVOID Buffer, SIZE_T Size, SIZE_T* NumberOfBytesWritten) 
	{
		SYSCALL_WRAPPER(NtWriteVirtualMemory, ProcessHandle, 
			BaseAddress, Buffer, Size, NumberOfBytesWritten)
	}
	NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, 
		ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) 
	{
		SYSCALL_WRAPPER(NtAllocateVirtualMemory, ProcessHandle, 
			BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
	}
	NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, 
		PSIZE_T RegionSize, ULONG FreeType) 
	{
		SYSCALL_WRAPPER(NtFreeVirtualMemory, ProcessHandle, 
			BaseAddress, RegionSize, FreeType)
	}
	NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, 
		MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, 
		SIZE_T Length, PSIZE_T ResultLength) 
	{
		SYSCALL_WRAPPER(NtQueryVirtualMemory, ProcessHandle, BaseAddress, 
			MemoryInformationClass, Buffer, Length, ResultLength)
	}
	NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, 
		PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) 
	{
		SYSCALL_WRAPPER(NtProtectVirtualMemory, ProcessHandle, BaseAddress, 
			NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection)
	}
	NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, 
		HANDLE ProcessHandle, PVOID StartAddress, PVOID Parameter, ULONG Flags, SIZE_T StackZeroBits, 
		SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID BytesBuffer) 
	{
		SYSCALL_WRAPPER(NtCreateThreadEx, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
			StartAddress, Parameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, BytesBuffer)
	}
	NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, 
		PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) 
	{
		SYSCALL_WRAPPER(NtQueryInformationProcess, ProcessHandle, 
			ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)
	}
	NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId) 
	{
		SYSCALL_WRAPPER(NtOpenProcess, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId)
	}
	NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, 
		PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) 
	{
		SYSCALL_WRAPPER(NtQuerySystemInformation, SystemInformationClass, 
			SystemInformation, SystemInformationLength, ReturnLength)
	}
	NTSTATUS NtSuspendProcess(HANDLE ProcessHandle) {
		SYSCALL_WRAPPER(NtSuspendProcess, ProcessHandle)
	}
	NTSTATUS NtResumeProcess(HANDLE ProcessHandle) {
		SYSCALL_WRAPPER(NtResumeProcess, ProcessHandle)
	}
} // namespace mango::windows