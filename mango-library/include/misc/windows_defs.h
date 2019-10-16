#pragma once

#include <Windows.h>
#include <winternl.h>


namespace mango {
	using NtQueryInformationProcessFn = NTSTATUS(__stdcall*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
} // namespace mango