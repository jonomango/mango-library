#pragma once

#include <exception>
#include <sstream>

#include "../crypto/string_encryption.h"


// for passing to our custom exceptions
#define mango_format_ntstatus(status) enc_str("NTSTATUS = 0x"), std::hex, std::uppercase, status

// can't really do this without a macro, oh well
#define mango_create_error(name, value)\
class name : public mango::MangoError {\
public:\
	template <typename ...Args>\
	name(Args&& ...info) : mango::MangoError(enc_str(value), info...) {}\
};

namespace mango {
	// base class of all mango-library exception
	class MangoError : public std::exception {
	public:
		template <typename ...Args>
		MangoError(const std::string& error, Args&& ...info) {
			this->m_value = error;

			// additional info
			std::ostringstream stream;
			(stream << ... << info);
			this->m_info = stream.str();
		}

		// get the error message
		const char* what() const noexcept override { return this->m_value.c_str(); }

		// additional info
		const std::string& info() const noexcept { return this->m_info; }

		// concat what() + info()
		std::string full_error() const noexcept { return this->m_value + enc_str(" Info: ") + this->m_info; }

	protected:
		std::string m_value,
			m_info;
	};

	mango_create_error(FunctionAlreadyHooked, "Function is already hooked.");

	mango_create_error(CantSetup64From32, "Cant setup a 64bit process from a 32bit process.");

	mango_create_error(NotWow64Process, "Process is not running under WOW64.");
	mango_create_error(NotA32BitProcess, "Process is not a 32bit process.");

	mango_create_error(InvalidProcessHandle, "Failed to get a valid process handle, usually caused by insufficient permissions or invalid process ID.");
	mango_create_error(InvalidFileHandle, "Failed to get a valid file handle, usually caused by a non-existant file.");
	mango_create_error(InvalidFileSize, "Invalid file size.");
	mango_create_error(InvalidPEHeader, "Invalid PE header.");
	mango_create_error(InvalidVtableSize, "Invalid VTable size, caused when VTable size is 0.");

	mango_create_error(FailedToQueryProcessArchitecture, "Failed to query process architecture type (x64 or x86).");
	mango_create_error(FailedToQueryProcessName, "Failed to query process name.");
	mango_create_error(FailedToQueryProcessInformation, "Failed to query process information.");
	mango_create_error(FailedToQuerySystemInformation, "Failed to query system information.");
	mango_create_error(FailedToReadMemory, "Failed to read process memory.");
	mango_create_error(FailedToWriteMemory, "Failed to write to process memory.");
	mango_create_error(FailedToAllocateVirtualMemory, "Failed to allocate virtual memory.");
	mango_create_error(FailedToFreeVirtualMemory, "Failed to free virtual memory.");
	mango_create_error(FailedToQueryMemoryProtection, "Failed to query memory pages' protection.");
	mango_create_error(FailedToSetMemoryProtection, "Failed to set memory pages' protection.");
	mango_create_error(FailedToGetFunctionAddress, "Failed to get function address.");
	mango_create_error(FailedToCreateRemoteThread, "Failed to create a thread in the process.");
	mango_create_error(FailedToEnumModules, "Failed to enum process modules.");
	mango_create_error(FailedToFindModule, "Failed to find module.");
	mango_create_error(FailedToFindImportModule, "Failed to find imported module in IAT.");
	mango_create_error(FailedToFindImportFunction, "Failed to find imported function in IAT.");
	mango_create_error(FailedToResolveImport, "Failed to resolve import when manually mapping image.");
	mango_create_error(FailedToReadFile, "Failed to read file.");
	mango_create_error(FailedToVerifyX64Transition, "Failed to verify against Wowx64Transition address.");
	mango_create_error(FailedToOpenProcessToken, "Failed to open process token.");
	mango_create_error(FailedToGetPrivilegeLUID, "Failed to get privilege LUID.");
	mango_create_error(FailedToSetTokenPrivilege, "Failed to set token's privileges.");
} // namespace mango