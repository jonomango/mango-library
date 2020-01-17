#include <epic/loader.h>
#include <epic/process.h>
#include <epic/pattern_scanner.h>
#include <epic/shellcode.h>
#include <epic/vmt_hook.h>
#include <epic/iat_hook.h>
#include <epic/syscalls.h>
#include <epic/syscall_hook.h>
#include <epic/unused_memory.h>
#include <epic/windows_defs.h>
#include <epic/driver.h>
#include <epic/read_write_variable.h>
#include <epic/vmt_helpers.h>
#include <misc/vector.h>
#include <misc/matrix.h>
#include <misc/color.h>
#include <misc/logger.h>
#include <misc/error_codes.h>
#include <misc/math.h>
#include <misc/fnv_hash.h>
#include <crypto/string_encryption.h>

#include "unit_tests.h"

#include <thread>
#include <sstream>
#include <fstream>


// TODO:
// std::source_location in exceptions when c++20 comes out
// improve manual mapper (tls callbacks)
// TODO: ApiSet in manual mapper and move more stuff out of the injected thread

int main() {
	mango::logger.set_channels(mango::basic_colored_logging());

	//run_unit_tests();

	mango::logger.info("info text here.");
	mango::logger.success("success text here.");
	mango::logger.warning("warning text here.");
	mango::logger.error("error text here.");

	try {
		using namespace mango;

	} catch (std::exception& e) {
		mango::logger.error(e.what());
	}

	std::system("pause");
	return 0;
}