#pragma once

#include <exception>
#include <sstream>

#include "../crypto/string_encryption.h"


// for passing to our custom exceptions
#define mango_format_ntstatus(status) enc_str("NTSTATUS = 0x"), std::hex, std::uppercase, status
#define mango_format_w32status(status) enc_str("Win32 error = 0x"), std::hex, std::uppercase, status

// can't really do this without a macro, oh well
#define mango_create_error(name, value)\
class name : public mango::MangoError {\
public:\
	template <typename ...Args>\
	name(Args&& ...info) : mango::MangoError(enc_str(value), ' ', info...) {}\
};

namespace mango {
	// base class of all mango-library exception
	class MangoError : public std::exception {
	public:
		template <typename ...Args>
		MangoError(Args&& ...info) {
			std::ostringstream stream;
			(stream << ... << info);
			this->m_value = stream.str();
		}

		// get the error message
		const char* what() const noexcept override { return this->m_value.c_str(); }

	protected:
		std::string m_value;
	};

	mango_create_error(IoControlFailed, "Call to DeviceIoControl failed.");

	mango_create_error(FunctionAlreadyHooked, "Function is already hooked.");

	mango_create_error(CantSetup64From32, "Cant setup a 64bit process from a 32bit process.");

	mango_create_error(NoAvailableDebugRegisters, "All debug registers are currently used.");

	mango_create_error(ApiSetInvalidName, "Provided ApiSet name doesn't begin with \"api-\" or \"ext-\".");
	mango_create_error(FailedToResolveApiSetName, "Failed to resolve ApiSet name.");

	mango_create_error(NotWow64Process, "Process is not running under WOW64.");
	mango_create_error(NotA32BitProcess, "Process is not a 32bit process.");
	mango_create_error(UnmatchingImageArchitecture, "Image architecture does not match the process architecture.");

	mango_create_error(InvalidProcessHandle, "Failed to get a valid process handle, usually caused by insufficient permissions or invalid process ID.");
	mango_create_error(InvalidFileHandle, "Failed to get a valid file handle.");
	mango_create_error(InvalidFileSize, "Invalid file size.");
	mango_create_error(InvalidPEHeader, "Invalid PE header.");
	mango_create_error(InvalidVtableSize, "Invalid VTable size, caused when VTable size is 0.");
	mango_create_error(InvalidConsoleHandle, "Failed to get console handle.");

	mango_create_error(FailedToGetFunctionAddress, "Failed to get function address.");
	mango_create_error(FailedToCreateRemoteThread, "Failed to create a thread in the process.");
	mango_create_error(FailedToEnumModules, "Failed to enum process modules.");
	mango_create_error(FailedToFindModule, "Failed to find module.");
	mango_create_error(FailedToFindImportModule, "Failed to find imported module in IAT.");
	mango_create_error(FailedToFindImportFunction, "Failed to find imported function in IAT.");
	mango_create_error(FailedToResolveImport, "Failed to resolve import when manually mapping image.");
	mango_create_error(FailedToReadFile, "Failed to read file.");
	mango_create_error(FailedToWriteFile, "Failed to write file.");
	mango_create_error(FailedToVerifyX64Transition, "Failed to verify against Wowx64Transition address.");
	mango_create_error(FailedToOpenProcessToken, "Failed to open process token.");
	mango_create_error(FailedToGetPrivilegeLUID, "Failed to get privilege LUID.");
	mango_create_error(FailedToSetTokenPrivilege, "Failed to set token's privileges.");
	mango_create_error(FailedToSuspendProcess, "Failed to suspend the process.");
	mango_create_error(FailedToResumeProcess, "Failed to resume the process.");
	mango_create_error(FailedToEnumProcesses, "Failed to enumerate all processes.");
	mango_create_error(FailedToGetThreadContext, "Failed to get thread context.");
	mango_create_error(FailedToSetThreadContext, "Failed to set thread context.");

	mango_create_error(FailedToReadMemory, "Failed to read process memory.");
	mango_create_error(FailedToWriteMemory, "Failed to write to process memory.");
	mango_create_error(FailedToAllocateVirtualMemory, "Failed to allocate virtual memory.");
	mango_create_error(FailedToFreeVirtualMemory, "Failed to free virtual memory.");
	mango_create_error(FailedToSetMemoryProtection, "Failed to set memory pages' protection.");

	mango_create_error(FailedToQueryProcessArchitecture, "Failed to query process architecture type (x64 or x86).");
	mango_create_error(FailedToQueryProcessName, "Failed to query process name.");
	mango_create_error(FailedToQueryProcessInformation, "Failed to query process information.");
	mango_create_error(FailedToQuerySystemInformation, "Failed to query system information.");
	mango_create_error(FailedToQueryMemoryProtection, "Failed to query memory pages' protection.");

	mango_create_error(FailedToOpenServiceControlManager, "Failed to open service control manager.");
	mango_create_error(FailedToOpenService, "Failed to open service.");
	mango_create_error(FailedToCreateService, "Failed to create service.");
	mango_create_error(FailedToStartService, "Failed to start service.");
	mango_create_error(FailedToStopService, "Failed to stop service.");
	mango_create_error(FailedToDeleteService, "Failed to delete service.");
} // namespace mango