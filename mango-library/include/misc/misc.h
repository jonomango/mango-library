#pragma once


namespace mango {
	template <typename T, T Value>
	constexpr T force_compile_time() {
		return Value;
	}
} // namespace mango