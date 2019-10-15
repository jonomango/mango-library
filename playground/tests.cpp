#include "tests.h"

#include <epic/process.h>
#include <epic/vmt_hook.h>
#include <epic/iat_hook.h>

#include <misc/unit_test.h>
#include <misc/error_codes.h>


class ExampleClass {
public:
	virtual int example_func() {
		return 1234'5678;
	}
};

void test_vmt_hooks(mango::Process& process) {
	mango::UnitTest unit_test("VmtHook");

	const auto example_instance = std::make_unique<ExampleClass>();
	mango::VmtHook vmt_hook;

	// vmt_hook is in an invalid state
	unit_test.expect_false(vmt_hook);
	unit_test.expect_false(vmt_hook.is_valid());

	vmt_hook.setup(process, example_instance.get());

	// vmt_hook is setup, it is now in an invalid state
	unit_test.expect_true(vmt_hook);
	unit_test.expect_true(vmt_hook.is_valid());

	// not hooked, should return 1234'5678
	unit_test.expect_value(example_instance->example_func(), 1234'5678);

	const auto hooked_func = [](void* ecx) -> int {
		return 8765'4321;
	};

	vmt_hook.hook<uintptr_t, int(__thiscall*)(void*)>(0, hooked_func);

	// can't hook same function twice
	unit_test.expect_custom([&]() {
		try {
			vmt_hook.hook<uintptr_t, int(__thiscall*)(void*)>(0, hooked_func);
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

	vmt_hook.hook<uintptr_t, int(__thiscall*)(void*)>(0, hooked_func);

	vmt_hook.release();

	// not hooked, should return 1234'5678
	unit_test.expect_value(example_instance->example_func(), 1234'5678);

	// vmt_hook was just released, it is now in an invalid state
	unit_test.expect_false(vmt_hook);
	unit_test.expect_false(vmt_hook.is_valid());
}

void test_iat_hooks(mango::Process& process) {
	mango::UnitTest unit_test("IatHook");

	mango::IatHook iat_hook;

	// not setup yet
	unit_test.expect_false(iat_hook);
	unit_test.expect_false(iat_hook.is_valid());

	iat_hook.setup(process, GetModuleHandle("kernel32.dll"));

	// setup
	unit_test.expect_true(iat_hook);
	unit_test.expect_true(iat_hook.is_valid());
}

void run_unit_tests() {
	try {
		mango::Process process(GetCurrentProcessId());

		test_vmt_hooks(process);
		test_iat_hooks(process);
	} catch (mango::MangoError& e) {
		mango::error() << "Exception caught: " << e.what() << std::endl;
	}
}