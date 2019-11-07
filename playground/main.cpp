#include <epic/loader.h>
#include <epic/process.h>
#include <epic/pattern_scanner.h>
#include <epic/shellcode.h>
#include <epic/vmt_hook.h>
#include <epic/syscalls.h>
#include <epic/syscall_hook.h>
#include <misc/vector.h>
#include <misc/logger.h>
#include <misc/error_codes.h>
#include <crypto/string_encryption.h>
#include <crypto/fnv_hash.h>

#include "unit_tests.h"

// TODO:
// std::source_location in exceptions when c++20 comes out
// improve manual mapper (apischema)

// setup logger channels
void setup_logger() {
	static const auto display_info = [](const uint16_t attribute, const std::string_view prefix, std::ostringstream&& ss) {
		static const auto handle = GetStdHandle(STD_OUTPUT_HANDLE);

		std::cout << '[';
		SetConsoleTextAttribute(handle, attribute);
		std::cout << prefix;
		SetConsoleTextAttribute(handle, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
		std::cout << "] " << ss.str() << std::endl;
	};

	// info channel
	mango::logger.set_info_channel([](std::ostringstream&& ss) {
		display_info(FOREGROUND_BLUE | FOREGROUND_GREEN, "info", std::move(ss));
	});

	// success channel
	mango::logger.set_success_channel([](std::ostringstream&& ss) {
		display_info(FOREGROUND_GREEN, "success", std::move(ss));
	});

	// error channel
	mango::logger.set_error_channel([](std::ostringstream&& ss) {
		display_info(FOREGROUND_RED, "error", std::move(ss));
	});

	mango::logger.success("Logging channels initialized.");
}


int main() {
	setup_logger();

	// in case we broke some shit
	run_unit_tests();

	// catch any exceptions
	try {
		const auto process = mango::Process::current();
	} catch (mango::MangoError& e) {
		mango::logger.error(e.what());
	} catch (std::exception& e) {
		mango::logger.error(e.what());
	}

	mango::logger.info("program end");
	getchar();
	return 0;
}