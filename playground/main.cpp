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
#include <misc/windows_defs.h>
#include <crypto/string_encryption.h>
#include <crypto/fnv_hash.h>

#include <Psapi.h>
#include <functional>
#include <intrin.h>

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

void syscall_hook(uint32_t syscall_index, uint32_t* stack) {
	static bool ignore_syscalls = false;
	if (ignore_syscalls)
		return;

	ignore_syscalls = true; {
		if (syscall_index == 63) {
			mango::logger.info("NtReadProcessMemory called.");
		}
	} ignore_syscalls = false;
}

int main() {
	setup_logger();

	// in case we broke some shit
	run_unit_tests();

	// mango::Process constructor should always be wrapped in a try-catch block
	try {
		mango::Process process(GetCurrentProcessId());

		mango::Wow64SyscallHook::SetupOptions options;
		options.m_auto_release = false;
		
		mango::Wow64SyscallHook hook(process, syscall_hook, options);

		int value_one = 0x69, value_two = 0x420;
		ReadProcessMemory(process.get_handle(), &value_one, &value_two, 4, nullptr);
		mango::logger.info(value_two);
		
	} catch (mango::MangoError& e) {
		mango::logger.error(e.what());
	} catch (std::exception& e) {
		mango::logger.error(e.what());
	}

	getchar();
	return 0;
}