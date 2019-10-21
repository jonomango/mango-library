#include "tests.h"

#include <epic/loader.h>
#include <epic/process.h>
#include <epic/pattern_scanner.h>
#include <epic/shellcode.h>
#include <misc/vector.h>
#include <misc/logger.h>
#include <misc/error_codes.h>
#include <misc/windows_defs.h>
#include <crypto/encrypted_string.h>
#include <crypto/fnv_hash.h>

#include <Psapi.h>
#include <functional>

// TODO:
// std::source_location in exceptions when c++20 comes out
// imported manual mapper (apischema + bug fix)
// maybe optional lazy module loader (at first access init the LoadedModule)
// defer module loading


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

	// mango::Process constructor should always be wrapped in a try-catch block
	try {
		mango::Process::SetupOptions options;
		options.m_defer_module_loading = true;

		mango::Process process(GetCurrentProcessId(), options);

		const char* text = "Hello world!";
		const auto hello_world_func = mango::Shellcode(
			"\x48\x83\xEC\x20", // sub rsp, 0x20
			"\x48\xB9", uint64_t(text), // mov rcx, text
			"\x48\xB8", uint64_t(&std::puts), // mov rax, &std::puts
			"\xFF\xD0", // call rax
			"\x48\x83\xC4\x20", // add rsp, 0x20
			"\xC3"
		).allocate(process);

		mango::Shellcode(
			"\x48\x83\xEC\x20", // sub rsp, 0x20
			"\x48\xB8", uint64_t(hello_world_func), // mov rax, hello_world_func
			"\xFF\xD0", // call rax
			"\x48\x83\xC4\x20", // add rsp, 0x20
			"\xC3"
		).execute(process);

		mango::Shellcode::free(process, hello_world_func);
	} catch (mango::MangoError& e) {
		mango::logger.error(e.what());
	}

	getchar();
	return 0;
}