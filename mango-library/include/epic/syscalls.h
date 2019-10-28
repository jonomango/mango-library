#pragma once

#include <stdint.h>
#include <string>

#include "../crypto/string_encryption.h"


namespace mango {
	// dynamically get the sycall index of a function in ntdll.dll
	uint32_t syscall_index(const std::string& func_name);

	// get address of Wow64Transition
	uint32_t get_x64transition();

	// verify that our hardcoded transition address is correct
	// should always be checked when using x86 syscalls
	// always returns true in 64 bit process
	bool verify_x64transition();

	// syscall.asm if compiled for x64
	extern "C" void _syscall_stub();

	// for x64
	template <typename Ret, 
		typename Arg1 = void*, 
		typename Arg2 = void*,
		typename Arg3 = void*,
		typename Arg4 = void*,
		typename ...Args>
	Ret _syscall64(const uint32_t index, 
		const Arg1 arg1 = nullptr, 
		const Arg2 arg2 = nullptr,
		const Arg3 arg3 = nullptr,
		const Arg4 arg4 = nullptr,
		const Args ...args) {
		// the index is the first parameter passed on the stack (not sure if should be 16 byte aligned since seems to work fine)
		return (reinterpret_cast<Ret(__stdcall*)(Arg1, Arg2, Arg3, Arg4,
			uint32_t, Args...)>(&_syscall_stub))(arg1, arg2, arg3, arg4, index, args...);
	}

	// syscall wrapper, based on https://www.unknowncheats.me/forum/c-and-c-/267587-comfy-direct-syscall-caller-x64.html
	// but adapted to also work with WOW64 processes
	template <typename Ret = void*, typename ...Args>
	Ret syscall(const uint32_t index, const Args ...args) {
		// cant use "if constexpr" cuz of __asm
#ifdef _WIN64
		return _syscall64<Ret>(index, args...);
#else 
		// this is the part that calls the syscall stub
		const auto ret = (reinterpret_cast<Ret(__stdcall*)(uint32_t, Args...)>(&_syscall_stub))(index, args...);

		// callee cleans up stack in __stdcall (which we cant dynamically do in the stub)
		constexpr auto size_of_args = (0 + ... + sizeof(Args));
		__asm add esp, size_of_args

		return ret;
#endif
	}
} // namespace mango