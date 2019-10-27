#include <epic/loader.h>
#include <epic/process.h>
#include <epic/pattern_scanner.h>
#include <epic/shellcode.h>
#include <epic/vmt_hook.h>
#include <epic/syscalls.h>
#include <misc/vector.h>
#include <misc/logger.h>
#include <misc/error_codes.h>
#include <misc/windows_defs.h>
#include <crypto/string_encryption.h>
#include <crypto/fnv_hash.h>

#include <Psapi.h>
#include <functional>

#include "unit_tests.h"

// TODO:
// std::source_location in exceptions when c++20 comes out
// improve manual mapper (apischema + bug fix)
// good wrapper for syscalls (maybe usermode hooks too?)
// x64 code from x86 (and vise versa)


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

NTSTATUS read_virtual_memory(const mango::Process& process, const void* const address, void* const buffer, const size_t size) {
	static const auto index = mango::syscall_index(enc_str("NtReadVirtualMemory"));
	return mango::syscall<NTSTATUS>(index, process.get_handle(), address, buffer, size, nullptr);
}

int main() {
	setup_logger();

	// in case we broke some shit
	run_unit_tests();

	// mango::Process constructor should always be wrapped in a try-catch block
	try {
		mango::Process process(GetCurrentProcessId());

		int value_one = 69, value_two = 420;
		read_virtual_memory(process, &value_one, &value_two, sizeof(value_one));
		mango::logger.info(value_two);
	} catch (mango::MangoError& e) {
		mango::logger.error(e.what());
	}

	getchar();
	return 0;
}

//BOOL WINAPI DllMain(
//	_In_ HINSTANCE hinstDLL,
//	_In_ DWORD     fdwReason,
//	_In_ LPVOID    lpvReserved
//) {
//	if (fdwReason == DLL_PROCESS_ATTACH)
//		std::cout << "Hello world!" << std::endl;
//	return TRUE;
//}