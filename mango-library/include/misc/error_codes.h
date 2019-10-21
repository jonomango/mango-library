#pragma once

#include <exception>


// can't really do this without a macro, oh well
#define mango_create_error(name, value)\
class name : public mango::MangoError {\
public:\
	virtual const char* what() const noexcept override {\
		return value;\
	}\
};

namespace mango {
	class MangoError : public std::exception {};

	mango_create_error(FunctionAlreadyHooked, "Function is already hooked.");

	mango_create_error(InvalidProcessHandle, "Failed to get a valid process handle. Usually caused by insufficient permissions or invalid process ID.");
	mango_create_error(InvalidFileHandle, "Failed to get a valid file handle. Usually caused by a non-existant file.");
	mango_create_error(InvalidFileSize, "Invalid file size.");
	mango_create_error(InvalidPEHeader, "Invalid PE header.");
	mango_create_error(InvalidVtableSize, "Invalid VTable size, caused when VTable size is 0.");

	mango_create_error(FailedToQueryProcessArchitecture, "Failed to query process architecture type (x64 or x86).");
	mango_create_error(FailedToQueryProcessName, "Failed to query process name.");
	mango_create_error(FailedToQueryProcessInformation, "Failed to query process information.");
	mango_create_error(FailedToReadMemory, "Failed to read process memory.");
	mango_create_error(FailedToWriteMemory, "Failed to write to process memory.");
	mango_create_error(FailedToAllocateVirtualMemory, "Failed to allocate virtual memory.");
	mango_create_error(FailedToFreeVirtualMemory, "Failed to free virtual memory.");
	mango_create_error(FailedToQueryMemoryProtection, "Failed to query memory pages' protection.");
	mango_create_error(FailedToSetMemoryProtection, "Failed to set memory pages' protection.");
	mango_create_error(FailedToGetFunctionAddress, "Failed to get function address.");
	mango_create_error(FailedToCreateRemoteThread, "Failed to create a thread in the process.");
	mango_create_error(FailedToEnumModules, "Failed to enum process modules.");
	mango_create_error(FailedToFindImportModule, "Failed to find imported module in IAT.");
	mango_create_error(FailedToFindImportFunction, "Failed to find imported function in IAT.");
	mango_create_error(FailedToResolveImport, "Failed to resolve import when manually mapping image.");
	mango_create_error(FailedToReadFile, "Failed to read file.");
} // namespace mango