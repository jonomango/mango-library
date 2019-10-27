#pragma once

#include <type_traits>
#include <cstring>


namespace mango {
	// template thingy poopoos must be compile time constants
	template <typename T, T Value>
	constexpr T compile_time() {
		return Value;
	}

	// seems pretty useless at first, but its needed for the automatic size deduction for strings
	class StringWrapper {
	public:
		template <typename T>
		constexpr StringWrapper(T&& str) : m_str(str), m_size(0) {
			if constexpr (std::is_array_v<std::remove_reference_t<T>>)
				this->m_size = sizeof(str) - 1;
			else
				this->m_size = strlen(str);
		}

		// getters
		constexpr const char* get_str() const { return this->m_str; }
		constexpr size_t get_size() const { return this->m_size; }

	private:
		size_t m_size;
		const char* const m_str;
	};
} // namespace mango