#pragma once

#include <stdint.h>
#include <string>

#include "../crypto/string_encryption.h"


namespace mango {
	// dynamically get the sycall index of a function in ntdll.dll
	uint32_t syscall_index(const std::string& func_name);

	// syscall.asm if compiled for x64
	namespace impl {
		extern "C" void _syscall();

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
				uint32_t, Args...)>(&impl::_syscall))(arg1, arg2, arg3, arg4, index, args...);
		}
	} // namespace impl

	// syscall wrapper, based on https://www.unknowncheats.me/forum/c-and-c-/267587-comfy-direct-syscall-caller-x64.html
	// but adapted to also work with WOW64 processes
	template <typename Ret = void*, typename ...Args>
	Ret syscall(const uint32_t index, const Args ...args) {
		if constexpr (sizeof(void*) == 8) {
			return impl::_syscall64<Ret>(index, args...);
		} else {
			// for x86
			return (reinterpret_cast<Ret(*)(uint32_t, Args...)>(&impl::_syscall))(index, args...);
		}
	}
} // namespace mango