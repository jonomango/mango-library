#pragma once

#include <stdint.h>

// windows :nauseated_face: 
#undef max

namespace mango {
	// not much variance, what did u expect from someone ill versed in cryptography
	constexpr uint64_t compile_time_key(const uint64_t stuff = 0) {
		// based on compile time
		const auto hours = uint64_t((__TIME__[0] - '0') * 10 + (__TIME__[1] - '0'));
		const auto minutes = uint64_t((__TIME__[3] - '0') * 10 + (__TIME__[4] - '0'));
		const auto seconds = uint64_t((__TIME__[6] - '0') * 10 + (__TIME__[7] - '0'));

		// [0, 86400] (86400 seconds in a day)
		const auto total = seconds + (minutes * 60) + (hours * 60 * 60);
		const auto frog = ((seconds + 1) * (minutes + 1) * (hours + 1) * (stuff + 1)) % 86400;

		constexpr auto constant = std::numeric_limits<uint64_t>::max() / 86400;
		return constant * ((total ^ frog) % 86400);
	}
} // namespace mango