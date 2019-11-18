#include "unit_tests.h"

#include <epic/process.h>
#include <epic/vmt_hook.h>
#include <epic/iat_hook.h>
#include <epic/syscall_hook.h>
#include <epic/shellcode.h>
#include <epic/loader.h>
#include <epic/loaded_module.h>
#include <epic/pattern_scanner.h>
#include <epic/syscalls.h>

#include <misc/misc.h>
#include <misc/unit_test.h>
#include <misc/error_codes.h>

#include <crypto/string_encryption.h>

#include <Psapi.h>
#include <string>
#include <iomanip>


void test_process(mango::Process& process) {
	mango::UnitTest unit_test("Process");

	// process is not initialized yet
	unit_test.expect_zero(process);
	unit_test.expect_zero(process.is_valid());

	process.setup(GetCurrentProcessId());

	// calling release multiple times is safe
	process.release();
	process.release();

	// initializing process with a bad pid should throw
	{
		mango::ScopeGuard _fail_test([&]() { unit_test.failure(); });

		try {
			process.setup(3);
		} catch (mango::MangoError&) {
			unit_test.success();
			_fail_test.cancel();
		}
	}

	// initialize with pid
	process.setup(GetCurrentProcessId());

	// or initialize with handle
	process.setup(GetCurrentProcess());

	// process is init now
	unit_test.expect_nonzero(process);
	unit_test.expect_nonzero(process.is_valid());

	// yes, this is our process
	unit_test.expect_nonzero(process.is_self());
	unit_test.expect_value(process.get_pid(), GetCurrentProcessId());

	// are we a 64bit process
	unit_test.expect_value(process.is_64bit(), sizeof(void*) == 8);

	// verify that it's getting the correct process name
	char process_name[512];
	GetModuleBaseName(GetCurrentProcess(), 0, process_name, 512);
	unit_test.expect_value(process.get_name(), process_name);

	// verify module addresses
	unit_test.expect_value(process.get_module_addr(), uintptr_t(GetModuleHandle(nullptr)));
	unit_test.expect_value(process.get_module_addr("kernel32.dll"), uintptr_t(GetModuleHandle("kernel32.dll")));

	// 32bit peb
	if (!process.is_64bit()) {
		const auto peb = process.get_peb32();
		unit_test.expect_value(peb.ImageBaseAddress, uintptr_t(GetModuleHandle(nullptr)));
		unit_test.expect_value(peb.BeingDebugged, IsDebuggerPresent());
	}

	// 64bit peb
	if (!process.is_64bit() || process.is_wow64()) {
		const auto peb = process.get_peb64();
		unit_test.expect_value(peb.ImageBaseAddress, uintptr_t(GetModuleHandle(nullptr)));
		unit_test.expect_value(peb.BeingDebugged, IsDebuggerPresent());
	}

	// LoadLibrary
	const auto kernel32dll = load_library(process, "kernel32.dll");
	unit_test.expect_value(kernel32dll, uintptr_t(LoadLibraryA("kernel32.dll")));

	// GetProcAddress
	unit_test.expect_value(process.get_proc_addr("kernel32.dll", "IsDebuggerPresent"), uintptr_t(IsDebuggerPresent));

	// allocating virtual memory
	const auto example_value = reinterpret_cast<int*>(process.alloc_virt_mem(4, PAGE_READWRITE));
	unit_test.expect_nonzero(example_value);

	// reading memory
	*example_value = 420;
	unit_test.expect_value(process.read<int>(example_value), 420);
	
	// writing memory
	process.write<int>(example_value, 69);
	unit_test.expect_value(*example_value, 69);
	unit_test.expect_value(process.read<int>(example_value), 69);

	// custom functions
	process.set_read_memory_func([](const mango::Process* process, const void* const address, void* const buffer, const size_t size) {
		*reinterpret_cast<uint32_t*>(buffer) = 0x420;
	});
	unit_test.expect_value(process.read<uint32_t>(0x69), 0x420);
	process.set_read_memory_func(mango::Process::default_read_memory_func);

	// make sure reading still uses default_read_memory_func
	unit_test.expect_value(process.read<int>(example_value), 69);

	// get/set page protection
	unit_test.expect_value(process.get_mem_prot(example_value), PAGE_READWRITE);
	unit_test.expect_value(process.set_mem_prot(example_value, 4, PAGE_READONLY), PAGE_READWRITE);
	unit_test.expect_value(process.get_mem_prot(example_value), PAGE_READONLY);
	unit_test.expect_value(process.set_mem_prot(example_value, 4, PAGE_READWRITE), PAGE_READONLY);

	// free memory
	process.free_virt_mem(example_value);

	// remote threads
	unit_test.expect_custom([&]() {
		static bool did_thread_run;
		did_thread_run = false;

		// this waits for the thread to finish so this is safe
		process.create_remote_thread(static_cast<int(__stdcall*)()>([]() {
			did_thread_run = true;
			return 0;
		}));

		return did_thread_run;
	});
}

void test_vmt_hooks(mango::Process& process) {
	mango::UnitTest unit_test("VmtHook");

	class ExampleClass {
	public:
		virtual int example_func() {
			return 1234'5678;
		}
	};

	const auto hooked_func = static_cast<int(__fastcall*)(void*, void*)>([](void* ecx, void*) -> int {
		return 8765'4321;
	});

	const auto example_instance = std::make_unique<ExampleClass>();
	mango::VmtHook vmt_hook;

	// vmt_hook is in an invalid state
	unit_test.expect_zero(vmt_hook);
	unit_test.expect_zero(vmt_hook.is_valid());

	vmt_hook.setup(process, example_instance.get());

	// calling release multiple times is safe
	vmt_hook.release();
	vmt_hook.release();

	mango::VmtHook::SetupOptions vmt_options;
	vmt_options.m_replace_table = true;

	vmt_hook.setup(process, example_instance.get(), vmt_options);

	// vmt_hook is setup, it is now in an invalid state
	unit_test.expect_nonzero(vmt_hook);
	unit_test.expect_nonzero(vmt_hook.is_valid());

	// not hooked, should return 1234'5678
	unit_test.expect_value(example_instance->example_func(), 1234'5678);

	const auto original_vtable = process.read<uintptr_t>(example_instance.get());

	vmt_hook.hook<uintptr_t>(0, hooked_func);

	// make sure we're placing the table and not the table contents
	unit_test.expect_nonzero(process.read<uintptr_t>(example_instance.get()) == original_vtable);

	// can't hook the same function twice
	unit_test.expect_custom([&]() {
		try {
			vmt_hook.hook<uintptr_t>(0, hooked_func);
			return false;
		} catch (mango::FunctionAlreadyHooked&) {
			return true;
		}
	});

	// function is now hooked, we expect 8765'4321
	unit_test.expect_value(example_instance->example_func(), 8765'4321);

	vmt_hook.unhook(0);

	// not hooked anymore, should return 1234'5678
	unit_test.expect_value(example_instance->example_func(), 1234'5678);
	unit_test.expect_value(process.read<uintptr_t>(example_instance.get()), original_vtable);

	const auto original = process.get_vfunc<uintptr_t>(example_instance.get(), 0);

	// make sure the original is correct
	unit_test.expect_value(vmt_hook.hook<uintptr_t>(0, hooked_func), original);

	// another check to make sure its hooked
	unit_test.expect_value(uintptr_t(hooked_func), process.get_vfunc<uintptr_t>(example_instance.get(), 0));

	vmt_hook.release();

	// not hooked, should return 1234'5678
	unit_test.expect_value(example_instance->example_func(), 1234'5678);

	// vmt_hook was just released, it is now in an invalid state
	unit_test.expect_zero(vmt_hook);
	unit_test.expect_zero(vmt_hook.is_valid());
}

void test_iat_hooks(mango::Process& process) {
	// full optimization on x86 seems to use direct calls to imported functions (not sure tho)
	if (sizeof(void*) == 4)
		return;

	mango::UnitTest unit_test("IatHook");

	const auto hooked_func = static_cast<int(WINAPI*)()>([]() {
		return 69;
	});

	mango::IatHook iat_hook;

	// not setup yet
	unit_test.expect_zero(iat_hook);
	unit_test.expect_zero(iat_hook.is_valid());

	iat_hook.setup(process, process.get_module_addr());

	// calling release multiple times is safe
	iat_hook.release();
	iat_hook.release();

	iat_hook.setup(process, process.get_module_addr());

	// setup
	unit_test.expect_nonzero(iat_hook);
	unit_test.expect_nonzero(iat_hook.is_valid());

	const auto volatile original = uintptr_t(IsDebuggerPresent);

	// hook() returns the original, verify this
	unit_test.expect_value(iat_hook.hook("kernel32.dll", "IsDebuggerPresent", hooked_func), original);

	// module doesn't exist
	unit_test.expect_custom([&]() {
		try {
			iat_hook.hook("123ABC", "123ABC", 0x69);
			return false;
		} catch (mango::FailedToFindImportModule&) {
			return true;
		}
	});

	// module exists, function does not
	unit_test.expect_custom([&]() {
		try {
			iat_hook.hook("kernel32.dll", "123ABC", 0x69);
			return false;
		} catch (mango::FailedToFindImportFunction&) {
			return true;
		}
	});

	// can't hook the same function twice
	unit_test.expect_custom([&]() {
		try {
			iat_hook.hook("kernel32.dll", "IsDebuggerPresent", 0x69);
			return false;
		} catch (mango::FunctionAlreadyHooked&) {
			return true;
		}
	});

	unit_test.expect_value(IsDebuggerPresent(), hooked_func());
	unit_test.expect_value(uintptr_t(IsDebuggerPresent), uintptr_t(hooked_func));

	iat_hook.unhook("kernel32.dll", "IsDebuggerPresent");

	// not hooked anymore
	unit_test.expect_value(uintptr_t(IsDebuggerPresent), original);

	iat_hook.release();

	// not in a valid state anymore
	unit_test.expect_zero(iat_hook);
	unit_test.expect_zero(iat_hook.is_valid());
}

void test_syscall_hooks(mango::Process& process) {
	// only works on wow64 process
	if (sizeof(void*) != 4)
		return;

	mango::UnitTest unit_test("Wow64SyscallHook");

	const auto syscall_callback = static_cast<bool(*)(const uint32_t, uint32_t* const, volatile uint32_t)>(
		[](const uint32_t syscall_index, uint32_t* const arguments, volatile uint32_t return_value) {
		if (syscall_index == mango::syscall_index("NtReadVirtualMemory")) {
			*reinterpret_cast<uint32_t*>(uintptr_t(arguments[1])) = 420;
			return_value = 0;
			return false;
		}
		return true;
	});

	mango::Wow64SyscallHook syscall_hook(process, uint32_t(uintptr_t(syscall_callback)));

	// overwrite the value in the syscall_callback
	int value = 69;
	ReadProcessMemory(process.get_handle(), &value, 0, 0, 0);
	unit_test.expect_value(value, 420);
}

// not much to test, mostly just makes sure that all the cancer template stuff compiles
void test_shellcode(mango::Process& process) {
	mango::UnitTest unit_test("Shellcode");

	mango::Shellcode shellcode;

	// empty obviously
	unit_test.expect_zero(shellcode.get_data().size());

	// should only have 1 byte
	unit_test.expect_value(shellcode.push(uint8_t(0x69)).get_data().size(), 1);
	unit_test.expect_value(shellcode.get_data()[0], uint8_t(0x69));

	// reset
	shellcode.clear();
	unit_test.expect_zero(shellcode.get_data().size());

	// multiple values
	shellcode.push(
		"\x01\x02",
		uint16_t(0x0403),
		uint32_t(69)
	);
	unit_test.expect_value(shellcode.get_data().size(), 8);
	unit_test.expect_value(*reinterpret_cast<uint32_t*>(shellcode.get_data().data()), 0x04030201);
	shellcode.clear();

	// null byte at beginning of string
	shellcode.push("\x00\x69");
	unit_test.expect_value(*reinterpret_cast<uint16_t*>(shellcode.get_data().data()), 0x6900);

	// allocate and write shellcode to memory
	const auto address = shellcode.allocate_and_write(process);
	unit_test.expect_nonzero(address);
	unit_test.expect_value(process.read<uint16_t>(address), 0x6900);

	shellcode.free(process, address);
}

void test_loaded_module(mango::Process& process) {
	mango::UnitTest unit_test("LoadedModule");

	mango::LoadedModule loaded_module;

	// not setup yet
	unit_test.expect_zero(loaded_module);
	unit_test.expect_zero(loaded_module.is_valid());

	loaded_module.setup(process, process.get_module_addr("ntdll.dll"));

	// success
	unit_test.expect_nonzero(loaded_module);
	unit_test.expect_nonzero(loaded_module.is_valid());
}

void test_pattern_scanner(mango::Process& process) {
	mango::UnitTest unit_test("PatternScanner");

	// generate random data
	static uint8_t random_data[512]; // has to be static (so it's not allocated on the stack)
	for (size_t i = 0; i < sizeof(random_data); ++i)
		random_data[i] = uint8_t(rand());

	std::ostringstream pattern;

	// uppercase, single spaces, no wildcards
	for (size_t i = 0; i < sizeof(random_data); ++i)
		pattern << std::setfill('0') << std::setw(2) << std::uppercase << std::hex << +random_data[i] << " ";
	unit_test.expect_value(mango::find_pattern(process, process.get_name(), pattern.str()), uintptr_t(&random_data));

	// lowercase, single spaces, no wildcards
	pattern.str("");
	for (size_t i = 0; i < sizeof(random_data); ++i)
		pattern << std::setfill('0') << std::setw(2) << std::hex << +random_data[i] << " ";
	unit_test.expect_value(mango::find_pattern(process, process.get_name(), pattern.str()), uintptr_t(&random_data));

	// lowercase, varying spaces, no wildcards
	pattern.str("");
	for (size_t i = 0; i < sizeof(random_data); ++i)
		pattern << std::setfill('0') << std::setw(2) << std::hex << +random_data[i] << std::string(rand() % 10, ' ');
	unit_test.expect_value(mango::find_pattern(process, process.get_name(), pattern.str()), uintptr_t(&random_data));

	// lowercase, varying spaces, with wildcards
	pattern.str("");
	for (size_t i = 0; i < sizeof(random_data); ++i) {
		if (rand() % 10)
			pattern << std::setfill('0') << std::setw(2) << std::hex << +random_data[i] << std::string(rand() % 10, ' ');
		else
			pattern << "?";
	}
	unit_test.expect_value(mango::find_pattern(process, process.get_name(), pattern.str()), uintptr_t(&random_data));

	// random pattern, shouldn't find anything
	pattern.str("");
	for (size_t i = 0; i < 512; ++i)
		pattern << std::setfill('0') << std::setw(2) << std::hex << rand() % 256;
	unit_test.expect_zero(mango::find_pattern(process, process.get_name(), pattern.str()));
}

void test_misc(mango::Process& process) {
	mango::UnitTest unit_test("Misc");

	using namespace std::string_literals;

	unit_test.expect_value(enc_str("testString12345"), "testString12345");
	unit_test.expect_value(enc_str("\x00hello world!"), "\x00hello world!"s);

	int dummy_value = 69;

	// scope guard
	{
		mango::ScopeGuard _guard([&]() { dummy_value = 420; });
		unit_test.expect_value(dummy_value, 69);
	}

	unit_test.expect_value(dummy_value, 420);

	{
		mango::ScopeGuard _guard([](int& ref_value) { 
			ref_value = 69; 
			throw std::runtime_error("ScopeGuard should not throw."); 
		}, std::ref(dummy_value));
	}

	unit_test.expect_value(dummy_value, 69);
}

// unit test everything
void run_unit_tests() {
	try {
		mango::Process process;
		test_process(process);
		test_vmt_hooks(process);
		test_iat_hooks(process);
		test_syscall_hooks(process);
		test_shellcode(process);
		test_loaded_module(process);
		test_pattern_scanner(process);
		test_misc(process);
	} catch (mango::MangoError& e) {
		mango::logger.error("Exception caught: ", e.what());
	}
}