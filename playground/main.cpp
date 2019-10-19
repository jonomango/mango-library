#include <iostream>

#include "tests.h"

#include <epic/process.h>
#include <misc/logger.h>
#include <misc/error_codes.h>
#include <misc/windows_defs.h>
#include <crypto/encrypted_string.h>
#include <crypto/fnv_hash.h>

// TODO:
// std::source_location in exceptions when c++20 comes out


int main() {
	try {
		mango::Process process(21072);
		std::cout << std::hex << process.find_signature("", "40 53 48 83 EC 20 48 8B 01") << std::endl;
	} catch (mango::MangoError & e) {
		mango::error() << e.what() << std::endl;
	}

	getchar();
	return 0;
}