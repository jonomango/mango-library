#pragma once

#include <tuple>


namespace mango {
	// based on https://www.drdobbs.com/cpp/generic-change-the-way-you-write-excepti/184403758
	// but refactored into modern c++ with support for more than one argument
	// NOTE: references must be passed using std::ref()
	template <typename Callable, typename... Args>
	class ScopeGuard {
	public:
		ScopeGuard(const Callable& callable, const Args& ...args)
			: m_callable{ callable }, m_arguments{ args... } {}

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
		const Callable m_callable;
		const Arguments m_arguments;
		bool m_should_cancel = false;
	};
} // namespace mango