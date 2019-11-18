#pragma once

#include <type_traits>


namespace mango::math {
	template <typename T>
	constexpr T pow(T&& first, const size_t second) {
		T total(1);
		for (size_t i = 0; i < second; ++i)
			total *= first;
		return total;
	}
} // namespace mango::math