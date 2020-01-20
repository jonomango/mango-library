#include <epic/process.h>
#include <misc/logger.h>

#include "unit_tests.h"


DWORD WINAPI test_thread(void*) {
	return 1;
}

int main() {
	mango::logger.set_channels(mango::basic_colored_logging());

	run_unit_tests();

	try {
		const auto process(mango::Process::current());

	} catch (std::exception& e) {
		mango::logger.error(e.what());
	}

	std::system("pause");
	return 0;
}