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
#include <misc/scope_guard.h>
#include <crypto/string_encryption.h>
#include <epic/hardware_breakpoint.h>

#include "unit_tests.h"

#include <thread>
#include <sstream>
#include <fstream>
#include <bitset>



void register_hwbp(const mango::Process& process, const HANDLE thread, const uintptr_t address, const size_t size) {
	uintptr_t size_mask(0);
	switch (size) {
	case 1: size_mask = 0b00; break;
	case 2: size_mask = 0b01; break;
	case 4: size_mask = 0b11; break;
	case 8: size_mask = 0b10; break;
	default: return;
	}

	// suspend current thread to safely get the context
	SuspendThread(thread);
	const mango::ScopeGuard _guard(&ResumeThread, thread);

	// we only care about debug registers
	CONTEXT context{ .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread, &context);

	for (size_t i(0); i < 4; ++i) {
		// https://www.codeproject.com/Articles/28071/Toggle-hardware-data-read-execute-breakpoints-prog
		const auto local_enable_mask(uintptr_t(1) << (i * 2));

		// skip debug registers that are already being used
		if (context.Dr7 & local_enable_mask)
			continue;

		mango::logger.info("Using debug register: ", i);

		// enable locally
		context.Dr7 |= local_enable_mask;

		// hardcoded to break on execution but other options are break on read/write
		static constexpr uintptr_t type_mask(0b00);
		
		// specify when the breakpoint should trigger
		context.Dr7 &= ~(uintptr_t(0b11) << (16 + i * 4)); // clear value
		context.Dr7 |= (type_mask) << (16 + i * 4);	       // set value
		
		// specify the breakpoint size
		context.Dr7 &= ~(uintptr_t(0b11) << (18 + i * 4)); // clear value
		context.Dr7 |= (size_mask) << (18 + i * 4);        // set value

		// break on our address
		(&context.Dr0)[i] = address;

		// set our new, modified, thread context
		SetThreadContext(thread, &context);

		return;
	}

	mango::logger.error("No debug registers are free :(");
}

// TODO:
// std::source_location in exceptions when c++20 comes out
// improve manual mapper (tls callbacks)
// TODO: ApiSet in manual mapper and move more stuff out of the injected thread

int cheese_frog = -1;

DWORD WINAPI new_thread(void*) {
	while (true) {
		const std::string message("frog");
		std::cout << message << std::endl;
		Sleep(1000);
	}

	return 1;
}

uintptr_t hook_addr = 0;

LONG WINAPI handler(const PEXCEPTION_POINTERS info) {
	if (info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		if (info->ContextRecord->Eip == hook_addr) {
			mango::logger.success("Exception hit! Address: 0x", std::hex, info->ContextRecord->Eip);
			info->ContextRecord->Dr7 = 0; // clear debug register to prevent infinite loop
			info->ContextRecord->EFlags |= 0x100; // set step flag
		} else {
			mango::hwbp::enable(*info->ContextRecord, hook_addr);
			info->ContextRecord->EFlags &= ~0x100; // clear step flag
		}
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {
	mango::logger.set_channels(mango::basic_colored_logging());

	//run_unit_tests();

	try {
		using namespace mango;

		const auto process(Process::current());
		
		hook_addr = uintptr_t(&new_thread) + 0x37;// 0x40;
		mango::logger.info("Setting HWBP at address: 0x", std::hex, hook_addr);
		
		// TODO: externally add veh
		// TODO: function for removing hwbp (searching through dr7 for active registers, then checking if any of those registers match the provided address)
		AddVectoredExceptionHandler(TRUE, &handler);
		const auto thread(CreateThread(nullptr, 0, new_thread, nullptr, 0, nullptr));
		
		hwbp::enable(process, thread, hook_addr);
	} catch (std::exception& e) {
		mango::logger.error(e.what());
	}

	std::system("pause");
	return 0;
}