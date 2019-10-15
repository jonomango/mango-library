#include "tests.h"

#include <epic/process.h>

#include <misc/logger.h>
#include <misc/error_codes.h>



class ExampleClass {
public:
	virtual int example_func() {
		return 12345678;
	}
};

template <typename A, typename B>
void unit_test_cmp(A&& a, B&& b) {
	if (a == b) {
		mango::info() << "Passed unit test." << std::endl;
	} else {
		mango::error() << "Failed unit test." << std::endl;
	}
}

void run_unit_tests() {
	try {
		mango::Process process(GetCurrentProcessId());

		// test vmt hooks
		{
			const auto example_instance = std::make_unique<ExampleClass>();

			unit_test_cmp(example_instance->example_func(), 12345678);



			unit_test_cmp(example_instance->example_func(), 12345678);
		}
	} catch (mango::MangoError& e) {
		mango::error() << "Exception caught: " << e.what() << std::endl;
	}
}