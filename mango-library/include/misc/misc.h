#pragma once

#include <type_traits>
#include <functional>
#include <cstring>
#include <string>


namespace mango {
	// template values must be compile time constants
	template <typename T, T Value>
	static constexpr inline T compile_time = Value;

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
	// but adapted for c++17
	class ScopeGuard {
	public:
		template <typename Callable, typename ...Args>
		ScopeGuard(Callable&& callable, Args&& ...args)
			: m_callable(std::bind(std::forward<Callable>(callable), std::forward<Args>(args)...)) {
		}

		// destructor shouldn't throw
		~ScopeGuard() {
			try {
				if (!this->m_should_cancel)
					this->m_callable();
			} catch (...) {}
		}

		// cancel the scope guard (and additional scope guards)
		template <typename ...ScopeGuards>
		void cancel(ScopeGuards&& ...guards) noexcept {
			this->m_should_cancel = true;
			(guards.cancel(), ...);
		}

	private:
		const std::function<void()> m_callable;
		bool m_should_cancel = false;
	};
} // namespace mango