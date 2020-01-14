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
// improve manual mapper (apischema + tls callbacks)


// setup logger channels
void setup_logger(std::ostream& stream = std::cout) {
	static const auto display_info = [&](const uint16_t attribute, const std::string_view prefix, std::ostringstream&& ss) {
		static const auto handle = GetStdHandle(STD_OUTPUT_HANDLE);

		stream << '[';
		SetConsoleTextAttribute(handle, attribute);
		stream << prefix;
		SetConsoleTextAttribute(handle, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
		stream << "] " << ss.str() << std::endl;
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

	run_unit_tests();

	try {
		const std::string name{ "ravioli" };
		switch (mango::Fnv1a<uint64_t>{ name }) {
		case mango::Fnv1a<uint64_t>{ "frog" }:
			break;
		case mango::Fnv1a<uint64_t>{ "fish" }:
			break;
		}
	} catch (std::exception& e) {
		mango::logger.error(e.what());
	}

	std::system("pause");
	return 0;
}