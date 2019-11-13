#pragma once

#include <type_traits>


namespace mango::math {
	template <typename X>
	constexpr X pow(X&& first, const size_t second) {
		X total(1);
		for (size_t i = 0; i < second; ++i)
			total *= first;
		return total;
	}
} // namespace mango::math