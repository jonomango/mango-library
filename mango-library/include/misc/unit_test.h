#pragma once

#include <string>

#include "logger.h"


namespace mango {
	// scope based unit testing class (single header)
	class UnitTest {
	public:
		UnitTest(std::string&& name) : m_name(name) {
			mango::info() << "Starting unit test: " << this->m_name << std::endl;
		}
		~UnitTest() {
			mango::info() << "Ending unit test: " << this->m_name << std::endl;
		}

		// custom check, return true/false in functor
		template <typename Func>
		void expect_custom(Func&& func) {
			const auto prefix = this->generate_test_prefix();

			if (func())
				mango::info() << prefix << "passed" << std::endl;
			else
				mango::error() << prefix << "failed" << std::endl;
		}

		// compare to an expected value
		template <typename T, bool print_expected = true>
		void expect_value(T&& value, T&& expected) {
			const auto prefix = this->generate_test_prefix();

			if (value == expected)
				mango::info() << prefix << "passed" << std::endl;
			else {
				if constexpr (print_expected)
					mango::error() << prefix << "failed, expected: " << expected << ", recieved: " << value << std::endl;
				else
					mango::error() << prefix << "failed" << std::endl;
			}
		}

		// check if true value (NOT the same as value == true)
		template <typename T>
		void expect_true(T&& value) {
			const auto prefix = this->generate_test_prefix();

			if (value)
				mango::info() << prefix << "passed" << std::endl;
			else
				mango::error() << prefix << "failed, expected: true, recieved: false" << std::endl;
		}

		// check if false value (NOT the same as value == false)
		template <typename T>
		void expect_false(T&& value) {
			const auto prefix = this->generate_test_prefix();

			if (!value)
				mango::info() << prefix << "passed" << std::endl;
			else
				mango::error() << prefix << "failed, expected: false, recieved: true" << std::endl;
		}

	private:
		std::string generate_test_prefix() {
			return "Test #" + std::to_string(++this->m_test_num) + ": ";
		}

	private:
		std::string m_name;
		size_t m_test_num = 0;
	};
} // namespace mango