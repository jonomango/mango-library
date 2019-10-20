#pragma once

#include <stdint.h>
#include <string>


namespace mango {
	class Process;

	// inject a dll into another process (using LoadLibrary)
	uintptr_t load_library(const Process& process, const std::string& dll_path);

	// manual map a dll into another process
	// SEVERE BUGS if module is already mapped into the process via LoadLibrary
	uintptr_t manual_map(const Process& process, const std::string& dll_path);
	uintptr_t manual_map(const Process& process, const uint8_t* const image);
} // namespace mango