#pragma once

#include <type_traits>
#include <cstring>


namespace mango {
	// template thingy poopoos must be compile time constants
	template <typename T, T Value>
	constexpr T compile_time() {
		return Value;
	}

	template <typename Callable, size_t... Is>
	constexpr void _for_constexpr(Callable&& callable, const size_t start, const size_t inc, std::index_sequence<Is...>) {
		(callable(start + (Is * inc)), ...);
	}

	// compile time for loop
	// eg: for (size_t i = Start; i < End; i += Inc)
	template <size_t Start, size_t End, size_t Inc, typename Callable>
	constexpr void for_constexpr(Callable&& callable) {
		constexpr auto count = (End - Start - 1) / Inc + 1;
		if constexpr (count > 0)
			_for_constexpr(std::forward<Callable>(callable), Start, Inc, std::make_index_sequence<count>());
	}

	// seems pretty useless at first, but its needed for the automatic size deduction for strings with null chars (ex: shellcode)
	class StringWrapper {
	public:
		template <typename T>
		constexpr StringWrapper(T&& str) : m_str(str), m_size(0) {
			if constexpr (std::is_array_v<std::remove_reference_t<T>>)
				this->m_size = sizeof(str) - 1;
			else
				this->m_size = strlen(str);
		}

		template <typename T>
		constexpr StringWrapper(T&& str, const size_t size) : m_str(str), m_size(size) {}

		// getters
		constexpr const char* get_str() const { return this->m_str; }
		constexpr size_t get_size() const { return this->m_size; }

	private:
		size_t m_size;
		const char* const m_str;
	};
} // namespace mango