#include <iostream>

#include "tests.h"

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


int main() {
	run_unit_tests();

	try {
		mango::Process process(GetCurrentProcessId());
		mango::info() << process.get_name() << std::endl;

		// print all exported functions in kernel32.dll
		for (const auto& [module_name, entry] : process.get_module("kernel32.dll")->get_exports()) {
			mango::info() << module_name << " " << std::hex << entry.m_address << std::endl;
		}
	} catch (mango::MangoError& e) {
		mango::error() << e.what() << std::endl;
	}

	getchar();
	return 0;
}