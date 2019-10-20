#include <iostream>

#include "tests.h"

#include <epic/loader.h>
#include <epic/process.h>
#include <epic/pattern_scanner.h>
#include <misc/vector.h>
#include <misc/logger.h>
#include <misc/error_codes.h>
#include <misc/windows_defs.h>
#include <crypto/encrypted_string.h>
#include <crypto/fnv_hash.h>

// TODO:
// std::source_location in exceptions when c++20 comes out
// fix manual mapper bug


// setup logger channels
void setup_logger() {
	static const auto set_attribute = [](const WORD attribute) {
		static const auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(handle, attribute);
	};

	// info channel (logger.info(...))
	mango::logger.set_info_channel([](std::stringstream&& ss) {
		std::cout << "[";
		set_attribute(FOREGROUND_BLUE | FOREGROUND_GREEN);
		std::cout << "info";
		set_attribute(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
		std::cout << "] " << ss.str() << std::endl;
	});

	// error channel (logger.error(...))
	mango::logger.set_error_channel([](std::stringstream&& ss) {
		std::cout << "[";
		set_attribute(FOREGROUND_RED);
		std::cout << "error";
		set_attribute(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
		std::cout << "] " << ss.str() << std::endl;
	});
}

int main() {
	setup_logger();

	// in case we broke some shit
	run_unit_tests();

	// mango::Process can throw exceptions
	try {
		mango::Process process(GetCurrentProcessId());
	} catch (mango::MangoError& e) {
		mango::logger.error(e.what());
	}

	getchar();
	return 0;
}