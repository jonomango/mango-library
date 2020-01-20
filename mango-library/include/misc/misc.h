#pragma once

#include <type_traits>
#include <cstring>
#include <string>
#include <string_view>
#include <algorithm>


namespace mango {
	// template values must be compile time constants
	template <auto Value>
	static constexpr inline auto compile_time = Value;

	template <bool is64bit>
	using PtrType = std::conditional_t<is64bit, uint64_t, uint32_t>;

	namespace impl {
		// helper function for for_constexpr
		template <typename Callable, size_t... Is>
		constexpr void _for_constexpr(Callable&& callable, const size_t start, const size_t inc, std::index_sequence<Is...>) {
			(callable(start + (Is * inc)), ...);
		}
	} // namespace impl

	// compile time for loop
	// eg: for (size_t i = Start; i < End; i += Inc)
	template <size_t Start, size_t End, size_t Inc, typename Callable>
	constexpr void for_constexpr(Callable&& callable) {
		constexpr auto count{ (End - Start - 1) / Inc + 1 };
		if constexpr (count > 0)
			impl::_for_constexpr(std::forward<Callable>(callable), Start, Inc, std::make_index_sequence<count>());
	}

	// wstring to string conversions
	std::string wstr_to_str(const std::wstring_view str);

	// whatever dude
	template <typename T>
	T tolower_t(const T c) {
		return T(std::tolower(c));
	}

	// converts str to all lowercase
	template <typename T>
	void str_tolower(T&& str) {
		std::transform(std::begin(std::forward<T>(str)), std::end(std::forward<T>(
			str)), std::begin(std::forward<T>(str)), tolower_t<char>);
	}

	// seems pretty useless at first, but its needed for the automatic size deduction for strings with null chars (ex: shellcode)
	class StringWrapper {
	public:
		template <typename T>
		constexpr StringWrapper(T&& str) : m_str{ str }, m_size{ 0 } {
			if constexpr (std::is_array_v<std::remove_reference_t<T>>) {
				this->m_size = sizeof(str) - 1;
			} else {
				this->m_size = strlen(str);
			}
		}

		template <typename T>
		constexpr StringWrapper(T&& str, const size_t size) : m_str{ str }, m_size{ size } {}

		// this is dangerous
		StringWrapper(const std::string& str) : m_str{ str.c_str() }, m_size{ str.size() } {}

		// getters
		constexpr const char* string() const { return this->m_str; }
		constexpr size_t size() const { return this->m_size; }

	private:
		const char* const m_str;
		size_t m_size;
	};
} // namespace mango