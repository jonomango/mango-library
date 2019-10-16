#pragma once

#include <string>

#include "logger.h"


namespace mango {
	// scope based unit testing class (single header)
	class UnitTest {
	public:
		UnitTest(std::string&& name) : m_name(name) {
			mango::info() << "Starting unit tests: " << this->m_name << std::endl;
		}
		~UnitTest() {
			if (this->m_failures > 0)
				mango::error() << "Ending unit tests: " << this->m_name << " (" << 
				this->m_successes << " successes, " << this->m_failures << " failures)" << std::endl;
			else
				mango::info() << "Ending unit tests: " << this->m_name << " (" << 
				this->m_successes << " successes, " << this->m_failures << " failures)" << std::endl;
		}

		// custom check, return true/false in functor
		template <typename Callable>
		void expect_custom(Callable&& func) {
			if (std::invoke(func))
				this->success();
			else
				this->failure();
		}

		// compare to an expected value
		template <typename T, typename U, bool print_expected = true>
		void expect_value(T&& value, U&& expected) {
			if (value == expected)
				this->success();
			else {
				if constexpr (!print_expected)
					this->failure();
				else
					this->failure("recieved: ", value, ", expected: ", expected);
			}
		}

		// check if nonzero value
		template <typename T>
		void expect_nonzero(T&& value) {
			if (value)
				this->success();
			else
				this->failure("recieved: false, expected: true");
		}

		// check if false (0)
		template <typename T>
		void expect_zero(T&& value) {
			if (!value)
				this->success();
			else
				this->failure("recieved: true, expected: false");
		}

	private:
		void success() {
			++this->m_successes;
			++this->m_test_num;
		}

		template <typename ...Args>
		void failure(Args&& ...args) {
			++this->m_failures;

			auto& stream = mango::error();

			// log it
			stream << "Test #" << ++this->m_test_num << ": failed";
			if (sizeof...(args)) {
				stream << ", ";
				(stream << ... << std::forward<Args>(args));
			}
			stream << std::endl;
		}

	private:
		std::string m_name;
		size_t m_test_num = 0,
			m_successes = 0,
			m_failures = 0;
	};
} // namespace mango