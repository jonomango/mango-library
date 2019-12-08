#pragma once

#include <type_traits>
#include <cstring>
#include <string>
#include <tuple>
#include <functional>


namespace mango {
	// template values must be compile time constants
	template <auto Value>
	static constexpr inline auto compile_time = Value;

	// helper function for for_constexpr
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

	// std::wstring and std::string conversions
	std::wstring str_to_wstr(const std::string& str);
	std::string wstr_to_str(const std::wstring& str);

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

	// based on https://www.drdobbs.com/cpp/generic-change-the-way-you-write-excepti/184403758
	// NOTE: references must be passed using std::ref()
	template <typename Callable, typename... Args>
	class ScopeGuard {
	public:
		ScopeGuard(const Callable& callable, const Args& ...args)
			: m_callable(callable), m_arguments(args...) {}

		~ScopeGuard() {
			// destructor shouldn't throw
			if (!this->m_should_cancel) try {
				this->invoke_callable(std::make_index_sequence<std::tuple_size_v<Arguments>>());
			} catch (...) {}
		}

		// cancel the scope guard (and additional scope guards)
		template <typename ...ScopeGuards>
		void cancel(ScopeGuards& ...guards) noexcept {
			this->m_should_cancel = true;
			(guards.cancel(), ...);
		}

	private:
		using Arguments = std::tuple<Args...>;

		// call the function
		template <size_t... Is>
		void invoke_callable(std::index_sequence<Is...>) {
			std::invoke(this->m_callable, std::get<Is>(this->m_arguments)...);
		}

	private:
		Callable m_callable;
		Arguments m_arguments;
		bool m_should_cancel = false;
	};
} // namespace mango