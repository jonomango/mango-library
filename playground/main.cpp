#include "unit_tests.h"

#include <epic/driver.h>
#include <epic/cpuid.h>
#include <epic/process.h>
#include <misc/logger.h>
#include <misc/scope_guard.h>
#include <crypto/string_encryption.h>

#include <epic/loaded_module.h>
#include <epic/memory_scanner.h>


int main() {
	mango::logger.set_channels(mango::basic_colored_logging());

	run_unit_tests();

	try {
		using namespace mango;

		const auto process(Process::current());

		static const auto my_double = std::make_unique<double>(69.0);
		memscn::scan(process, { "00 00 00 00 00 40 51 40" }, "playground-x86.exe");
		memscn::scan(process, { "00 00 00 00 00 40 51 40" });
		memscn::scan(process, { "\x00\x00\x00\x00\x00\x40\x51\x40", "XXXXXXXX" });
		memscn::scan(process, { "\x00\x00\x00\x00\x00\x40\x51\x40", sizeof(double) });
		memscn::scan(process, { my_double.get(), sizeof(double) });
	} catch (const std::exception& e) {
		mango::logger.error(e.what());
	}

	std::system("pause");
	return 0;
}