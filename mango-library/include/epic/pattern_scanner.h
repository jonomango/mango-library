#pragma once

#include <stdint.h>
#include <string>


namespace mango {
	class Process;

	// find a pattern, IDA-style (example: "12 ? 34 ? ? 45 F9")
	uintptr_t find_pattern(const Process& process, const std::string& module_name, const std::string_view& pattern);
} // namespace mango