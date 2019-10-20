#include "../../include/epic/pattern_scanner.h"

#include "../../include/epic/process.h"


namespace mango {
	// find a pattern, IDA-style (example: "12 ? 34 ? ? 45 F9")
	uintptr_t find_pattern(const Process& process, const std::string& module_name, const std::string_view& pattern) {
		// take 2 chars (ex: 'F' and 'F') and return the byte (0xFF)
		const auto parse_byte = [](const char c1, const char c2) {
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

		const auto mod = process.get_module(module_name);
		if (!mod)
			return 0;

		// from the start of the module memory to the end
		const auto start = mod->get_image_base(),
			end = start + mod->get_image_size();

		// read
		const auto buffer = new uint8_t[end - start];
		process.read(start, buffer, end - start);

		// check for matching sequence
		for (uintptr_t current = start; current < (end - pattern.size()); current += 1) {
			size_t j = 0;
			bool pattern_matches = true;
			for (size_t i = 0; i < pattern.size(); ++i) {
				if (pattern[i] == ' ')
					continue;

				// wildcard
				j += 1;
				if (pattern[i] == '?')
					continue;

				// check if byte matches
				if (buffer[(current - start) + j - 1] == parse_byte(std::toupper(pattern[i]), std::toupper(pattern[i + 1]))) {
					i += 1;
					continue;
				}

				pattern_matches = false;
				break;
			}

			// found pattern
			if (pattern_matches) {
				delete[] buffer;
				return current;
			}
		}

		delete[] buffer;
		return 0;
	}
} // namespace mango