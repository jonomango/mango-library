#include "../../include/epic/pattern_scanner.h"

#include "../../include/epic/process.h"
#include "../../include/misc/error_codes.h"
#include "../../include/misc/misc.h"

#include <memory>


namespace mango {
	// find the first occurence of a pattern, IDA-style (example: "12 ? 34 ? ? 45 F9")
	// input bytes have to be 2 characters wide and wildcards always a single question mark
	// input is case insensitive and spaces are completely ignored
	// these two patterns are treated the same: "25 ? F3 ? 14 ? ? C9" && "25?f3?14??c9"
	uintptr_t find_pattern(const Process& process, const std::string_view module_name, const std::string_view pattern) {
		const auto values{ find_all_patterns(process, module_name, pattern) };
		return values.empty() ? 0 : values.front();
	}

	// same as find_pattern() but returns all occurences
	std::vector<uintptr_t> find_all_patterns(const Process& process, const std::string_view module_name, const std::string_view pattern) {
		const auto mod{ process.get_module(module_name) };
		if (!mod)
			throw FailedToFindModule{};

		// from the start of the module memory to the end
		const auto start{ mod->get_image_base() },
			end{ start + mod->get_image_size() };

		// read
		const auto buffer{ std::make_unique<uint8_t[]>(end - start) };
		process.read(start, buffer.get(), end - start);

		// translate two chars into their byte representation
		// i.e 'F' and 'F' turn into 0xFF
		const auto parse_byte{ [](char c1, char c2) {
			c1 = char(std::toupper(c1));
			c2 = char(std::toupper(c2));

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
		} };

		// if above 0xFF then wildcards follow
		std::vector<uint16_t> raw_pattern{};
		for (size_t i{ 0 }; i < pattern.size(); ++i) {
			if (pattern[i] == ' ')
				continue;

			// wildcards
			if (pattern[i] == '?') {
				if (!raw_pattern.empty() && raw_pattern.back() >= 0x100) {
					raw_pattern.back() += 1;
				} else {
					raw_pattern.push_back(0x100);
				}
			} else {
				raw_pattern.push_back(parse_byte(pattern[i], pattern[i + 1]));

				// skip the next char
				i += 1;
			}
		}

		std::vector<uintptr_t> found_patterns{};

		// check for matching sequence
		for (uintptr_t current{ start }; current < (end - raw_pattern.size()); ++current) {
			bool does_match{ true };

			// check if pattern matches
			for (size_t i{ 0 }, j = 0; i < raw_pattern.size(); ++i, ++j) {
				if (raw_pattern[i] >= 0x100) {
					// skip all the consecutive wildcards at once
					j += raw_pattern[i] - 0x100;
					continue;
				}

				if (uint8_t(raw_pattern[i]) != buffer[(current - start) + j]) {
					does_match = false;
					break;
				}
			}

			// if it matches, add to list
			if (does_match)
				found_patterns.emplace_back(current);
		}

		return found_patterns;
	}
} // namespace mango