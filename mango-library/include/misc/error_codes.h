#pragma once

#include <exception>


// can't really do this without a macro, oh well
#define MANGO_CREATE_ERROR(name, value)\
class name : public mango::MangoError {\
public:\
	virtual const char* what() const noexcept override {\
		return value;\
	}\
};

namespace mango {
	using MangoError = std::exception;

	MANGO_CREATE_ERROR(InvalidProcessHandle, "Failed to get a valid process handle. Usually caused by insufficient permissions or invalid process ID.");
	MANGO_CREATE_ERROR(InvalidFileHandle, "Failed to get a valid file handle. Usually caused by a non-existant file.");
	MANGO_CREATE_ERROR(InvalidFileSize, "Invalid file size.");
	MANGO_CREATE_ERROR(InvalidPEHeader, "Invalid PE header.");

	MANGO_CREATE_ERROR(FunctionAlreadyHooked, "Function is already hooked.");

	MANGO_CREATE_ERROR(FailedToQueryProcessArchitecture, "Failed to query process architecture type (x64 or x86).");
	MANGO_CREATE_ERROR(FailedToQueryProcessName, "Failed to query process name.");
	MANGO_CREATE_ERROR(FailedToQueryProcessInformation, "Failed to query process information.");
	MANGO_CREATE_ERROR(FailedToReadMemory, "Failed to read process memory.");
	MANGO_CREATE_ERROR(FailedToWriteMemory, "Failed to write to process memory.");
	MANGO_CREATE_ERROR(FailedToAllocateVirtualMemory, "Failed to allocate virtual memory.");
	MANGO_CREATE_ERROR(FailedToFreeVirtualMemory, "Failed to free virtual memory.");
	MANGO_CREATE_ERROR(FailedToQueryMemoryProtection, "Failed to query memory pages' protection.");
	MANGO_CREATE_ERROR(FailedToSetMemoryProtection, "Failed to set memory pages' protection.");
	MANGO_CREATE_ERROR(FailedToGetFunctionAddress, "Failed to get function address.");
	MANGO_CREATE_ERROR(FailedToCreateRemoteThread, "Failed to create a thread in the process.");
	MANGO_CREATE_ERROR(FailedToUpdateModules, "Failed to load process modules.");
	MANGO_CREATE_ERROR(FailedToFindImportModule, "Failed to find imported module in IAT.");
	MANGO_CREATE_ERROR(FailedToFindImportFunction, "Failed to find imported function in IAT.");
	MANGO_CREATE_ERROR(FailedToReadFile, "Failed to read file.");
} // namespace mango