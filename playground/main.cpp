#include <epic/loader.h>
#include <epic/process.h>
#include <epic/pattern_scanner.h>
#include <epic/shellcode.h>
#include <epic/vmt_hook.h>
#include <epic/iat_hook.h>
#include <epic/syscalls.h>
#include <epic/wow64_syscall_hook.h>
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
#include <epic/shellcode_wrappers.h>
#include <crypto/string_encryption.h>
#include <epic/hardware_breakpoint.h>

#include "unit_tests.h"

#include <thread>
#include <sstream>
#include <fstream>
#include <bitset>

#pragma comment(lib, "kernel32.lib")



// TODO:
// std::source_location in exceptions when c++20 comes out
// improve manual mapper (tls callbacks)
// TODO: ApiSet in manual mapper and move more stuff out of the injected thread

DWORD WINAPI new_thread(void*) {
	while (true) {
		const std::string message("frog");
		std::cout << message << std::endl;
		Sleep(1000);
	}

	return 1;
}

LONG WINAPI veh(const PEXCEPTION_POINTERS info) {
	return EXCEPTION_CONTINUE_SEARCH;
}

void __fastcall callback(const PEXCEPTION_POINTERS info) {
	mango::logger.info("Hook called! Address: 0x", std::hex, info->ContextRecord->Rip);
}

template <typename Ptr>
struct _RTL_VECTORED_EXCEPTION_HANDLER {
	Ptr Flink;
	Ptr Blink;
	ULONG Refs;
	Ptr VectoredHandler;
};

using RTL_VECTORED_EXCEPTION_HANDLER_M32 = _RTL_VECTORED_EXCEPTION_HANDLER<uint32_t>;
using RTL_VECTORED_EXCEPTION_HANDLER_M64 = _RTL_VECTORED_EXCEPTION_HANDLER<uint64_t>;

template <bool is64bit>
void insert_vectored_exception_handler(const mango::Process& process, const uintptr_t handler) {
	// https://docs.microsoft.com/en-us/archive/msdn-magazine/2001/september/under-the-hood-new-vectored-exception-handling-in-windows-xp

	using ListNode = _RTL_VECTORED_EXCEPTION_HANDLER<mango::PtrType<is64bit>>;
	ListNode* const veh_linked_list_head(reinterpret_cast<ListNode*>(process.get_module_addr("ntdll.dll") + 0x17A3C8));

	const auto encrypt_ptr = [&](const uintptr_t ptr) {
		using RtlEncodeRemotePointerFn = decltype(&EncodeRemotePointer);
		const auto func = RtlEncodeRemotePointerFn(process.get_proc_addr("ntdll.dll", "RtlEncodeRemotePointer"));

		PVOID decrypted = PVOID(ptr), encrypted = 0;
		func(process.get_handle(), decrypted, &encrypted);
		return uintptr_t(encrypted);
	};

	auto new_entry = new ListNode{
		.Flink = veh_linked_list_head->Flink,
		.Blink = uintptr_t(veh_linked_list_head),
		.Refs = 1,
		.VectoredHandler = encrypt_ptr(handler)
	};
	
	mango::logger.info(std::hex, veh_linked_list_head->Blink);
	mango::logger.info(std::hex, veh_linked_list_head->Flink);

	const auto CrossProcessFlags_addr = process.get_peb64_addr() + offsetof(mango::PEB_M64, CrossProcessFlags);
	process.write<uint8_t>(CrossProcessFlags_addr, process.read<uint8_t>(CrossProcessFlags_addr) | (1 << 2));

	// FUCKING HELL, totally forgot about ntdll.dll and the fucking .mrdata section
	// guess its time for more shellcode :/
	reinterpret_cast<ListNode*>(veh_linked_list_head->Flink)->Blink = uintptr_t(new_entry);
	veh_linked_list_head->Flink = uintptr_t(new_entry);
}

int main() {
	mango::logger.set_channels(mango::basic_colored_logging());

	//run_unit_tests();

	try {
		using namespace mango;

		const auto process(Process::current());

		const auto veh_list_head((RTL_VECTORED_EXCEPTION_HANDLER_M64*)(process.get_module_addr("ntdll.dll") + 0x17A3C8));
		
		mango::logger.info(process.get_peb64().ProcessUsingVEH);

		//AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)veh);
		insert_vectored_exception_handler<true>(process, uintptr_t(veh));

		mango::logger.info(process.get_peb64().ProcessUsingVEH);

		using RtlDecodeRemotePointerFn = decltype(&DecodeRemotePointer);
		const auto RtlDecodeRemotePointer = RtlDecodeRemotePointerFn(process.get_proc_addr("ntdll.dll", "RtlDecodeRemotePointer"));

		auto entry = veh_list_head;
		if (entry) {
			do {
				PVOID Ptr = PVOID(entry->VectoredHandler), DecodedPtr = nullptr;
				RtlDecodeRemotePointer(process.get_handle(), Ptr, &DecodedPtr);
				mango::logger.info("0x", DecodedPtr);

				entry = (RTL_VECTORED_EXCEPTION_HANDLER_M64*)entry->Flink;
			} while (entry != veh_list_head);
		}
		
		//const auto hook_address(uintptr_t(&new_thread) + 0x40);// 0x40;
		//mango::logger.info("Setting HWBP at address: 0x", std::hex, hook_address);
		//
		//const Shellcode shellcode(shw::debug_register_veh<true>(hook_address, uintptr_t(callback)));
		//const auto shellcode_addr(shellcode.allocate_and_write(process));
		//
		//// TODO: externally add veh
		//AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)shellcode_addr);
		//const auto thread(CreateThread(nullptr, 0, new_thread, nullptr, 0, nullptr));
		//
		//Sleep(50);
		//hwbp::enable(process, thread, hook_address);
	} catch (std::exception& e) {
		mango::logger.error(e.what());
	}

	std::system("pause");
	return 0;
}