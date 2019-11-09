#pragma once

#include <string>

#include "logger.h"


namespace mango {
	// scope based unit testing class (single header)
	class UnitTest {
	public:
		UnitTest(const std::string& name) : m_name(name) {
			mango::logger.info("Starting unit tests: ", this->m_name);
		}
		~UnitTest() {
			if (this->m_failures > 0)
				mango::logger.error("Ending unit tests: ", this->m_name, " (", 
				this->m_successes, " successes, ", this->m_failures, " failures)");
			else
				mango::logger.info("Ending unit tests: ", this->m_name, " (", 
				this->m_successes, " successes, ", this->m_failures, " failures)");
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

		void success() {
			++this->m_successes;
			++this->m_test_num;
		}

		// pass the reason for failure
		template <typename ...Args>
		void failure(Args&& ...args) {
			++this->m_failures;

			// if no reason
			if (sizeof...(args) <= 0) {
				mango::logger.error("Test #", ++this->m_test_num, ": failed");
				return;
			}

			mango::logger.error("Test #", ++this->m_test_num, ": failed, ", args...);
		}

	private:
		std::string m_name;
		size_t m_test_num = 0,
			m_successes = 0,
			m_failures = 0;
	};
} // namespace mango