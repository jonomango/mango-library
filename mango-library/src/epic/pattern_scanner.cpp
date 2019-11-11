#include "../../include/epic/pattern_scanner.h"

#include "../../include/epic/process.h"
#include "../../include/misc/error_codes.h"
#include "../../include/misc/misc.h"

#include <memory>


namespace {
	// take 2 chars (ex: 'F' and 'F') and return the byte (0xFF)
	uint8_t parse_byte(char c1, char c2) {
		c1 = std::toupper(c1);
		c2 = std::toupper(c2);

		uint8_t b = 0;
		if (c1 >= '0' && c1 <= '9')
			b += uint8_t((c1 - '0') * 16);
		else
			b += uint8_t((10 + (c1 - 'A')) * 16);

		if (c2 >= '0' && c2 <= '9')
			b += uint8_t(c2 - '0');
		else
			b += uint8_t(10 + (c2 - 'A'));
		return b;
	};
} // namespace

namespace mango {
	// find the first occurence of a pattern, IDA-style (example: "12 ? 34 ? ? 45 F9")
	// input bytes have to be 2 characters wide and wildcards always a single question mark
	// input is case insensitive and spaces are completely ignored
	// these two patterns are treated the same: "25 ? F3 ? 14 ? ? C9" && "25?f3?14??c9"
	uintptr_t find_pattern(Process& process, const std::string& module_name, const std::string_view& pattern) {
		const auto values = find_all_patterns(process, module_name, pattern);
		return values.empty() ? 0 : values.front();
	}

	// same as find_pattern() but returns all occurences
	std::vector<uintptr_t> find_all_patterns(Process& process, const std::string& module_name, const std::string_view& pattern) {
		const auto mod = process.get_module(module_name);
		if (!mod)
			throw FailedToFindModule();

		// from the start of the module memory to the end
		const auto start = mod->get_image_base(),
			end = start + mod->get_image_size();

		// read
		const auto buffer = std::make_unique<uint8_t[]>(end - start);
		process.read(start, buffer.get(), end - start);

		std::vector<uintptr_t> found_patterns;

		// check for matching sequence
		for (uintptr_t current = start; current < (end - pattern.size()); current += 1) {
			// add pattern at the end of scope (unless canceled of course)
			ScopeGuard _add_pattern([&]() { found_patterns.emplace_back(current); });

			// check if pattern matches
			size_t current_byte_index = 0;
			for (size_t i = 0; i < pattern.size(); ++i) {
				if (pattern[i] == ' ')
					continue;

				// wildcard
				current_byte_index += 1;
				if (pattern[i] == '?')
					continue;

				// sanity check 
				const auto curr_index = (current - start) + current_byte_index - 1;
				if (curr_index >= end - start)
					return found_patterns;

				// check if byte matches
				if (buffer[curr_index] == parse_byte(pattern[i], pattern[i + 1])) {
					i += 1;
					continue;
				}

				_add_pattern.cancel();
				break;
			}
		}

		return found_patterns;
	}
} // namespace mango