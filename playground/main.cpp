#include "unit_tests.h"

#include <epic/process.h>
#include <epic/hardware_breakpoint.h>
#include <misc/logger.h>
#include <misc/scope_guard.h>


DWORD WINAPI test_thread(void*) {
	return 1;
}

int main() {
	mango::logger.set_channels(mango::basic_colored_logging());

	run_unit_tests();

	try {
		const auto process(mango::Process::current());
		mango::logger.success("Attached to process - ", process.get_name());

		//const auto thread = CreateThread(nullptr, 0, test_thread, nullptr, 0, nullptr);
		//const mango::ScopeGuard _guard(&CloseHandle, thread);

		//int testvar = 0;
		//mango::hwbp::enable(process, GetCurrentThread(), uintptr_t(&testvar), {
		//	.type = mango::hwbp::Type::readwrite,
		//	.size = mango::hwbp::Size::four
		//});
		//mango::logger.success("Set hardware breakpoint on address 0x", &testvar);
		//
		////testvar = 69;
		//mango::logger.info("Value of testvar: ", testvar);
	} catch (const std::exception& e) {
		mango::logger.error(e.what());
	}

	std::system("pause");
	return 0;
}