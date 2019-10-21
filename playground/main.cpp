#include <epic/loader.h>
#include <epic/process.h>
#include <epic/pattern_scanner.h>
#include <epic/shellcode.h>
#include <epic/vmt_hook.h>
#include <misc/vector.h>
#include <misc/logger.h>
#include <misc/error_codes.h>
#include <misc/windows_defs.h>
#include <crypto/encrypted_string.h>
#include <crypto/fnv_hash.h>

#include <Psapi.h>
#include <functional>

#include "unit_tests.h"

// TODO:
// std::source_location in exceptions when c++20 comes out
// improve manual mapper (apischema + bug fix)


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
		mango::Process::SetupOptions process_options;
		process_options.m_defer_module_loading = true;

		mango::Process process(GetCurrentProcessId(), process_options);

		class ExampleClass {
		public:
			virtual void example_func() {
				mango::logger.info("example_func()");
			}
		};

		const auto hooked_func = static_cast<void(__thiscall*)(void*)>([](void*) {
			mango::logger.info("hooked_func()");
		});

		const auto example_a = std::make_unique<ExampleClass>();
		const auto example_b = std::make_unique<ExampleClass>();

		mango::logger.info("A before: ", std::hex, process.read<uintptr_t>(example_a.get()));
		mango::logger.info("B before: ", std::hex, process.read<uintptr_t>(example_b.get()));

		mango::VmtHook::SetupOptions vmt_options;
		vmt_options.m_replace_table = true;
	
		mango::VmtHook vmt_hook(process, example_a.get(), vmt_options);
		vmt_hook.hook(0, hooked_func);

		mango::logger.info("A after: ", std::hex, process.read<uintptr_t>(example_a.get()));
		mango::logger.info("B after: ", std::hex, process.read<uintptr_t>(example_b.get()));

		example_a->example_func();
		example_b->example_func();
		
	} catch (mango::MangoError& e) {
		mango::logger.error(e.what());
	}

	getchar();
	return 0;
}