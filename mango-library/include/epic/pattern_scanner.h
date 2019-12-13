#pragma once

#include <stdint.h>
#include <string>
#include <vector>


namespace mango {
	class Process;

	// find the first occurence of a pattern, IDA-style (example: "12 ? 34 ? ? 45 F9")
	// input bytes have to be 2 characters wide and wildcards always a single question mark
	// input is case insensitive and spaces are completely ignored
	// these two patterns are treated the same: "25 ? F3 ? 14 ? ? C9" && "25?f3?14??c9"
	uintptr_t find_pattern(const Process& process, const std::string_view module_name, const std::string_view pattern);

	// same as find_pattern() but returns all occurences
	std::vector<uintptr_t> find_all_patterns(const Process& process, const std::string_view module_name, const std::string_view pattern);
} // namespace mango