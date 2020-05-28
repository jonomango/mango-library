#pragma once

#include <stdint.h>
#include <string>


namespace mango::syscall {
	namespace impl {
		// syscall.asm if compiled for x64
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
				const Args ...args) 
		{
			// the index is the first parameter passed on the stack (not sure if should be 16 byte aligned since seems to work fine)
			return (reinterpret_cast<Ret(__stdcall*)(Arg1, Arg2, Arg3, Arg4,
				uint32_t, Args...)>(&_syscall))(arg1, arg2, arg3, arg4, index, args...);
		}

		template <typename T>
		void assert_valid_arg_size(T) {
			static_assert(sizeof(T) <= sizeof(void*), "Argument type size is too big.");
		}
	} // namespace impl

	// dynamically get the sycall index of a function in ntdll.dll
	uint32_t index(const std::string& func_name);

	// syscall wrapper, based on https://www.unknowncheats.me/forum/c-and-c-/267587-comfy-direct-syscall-caller-x64.html
	// but adapted to also work with WOW64 processes
	template <typename Ret = long, typename ...Args>
	Ret call(const uint32_t index, const Args ...args) {
		// make sure return type size is <= ptr size
		static_assert(sizeof(Ret) <= sizeof(void*), "Return type size is too big.");

		// make sure the arguments' size are <= ptr size
		(impl::assert_valid_arg_size(args), ...);

		if constexpr (sizeof(void*) == 8) {
			// for x64
			return impl::_syscall64<Ret>(index, args...);
		} else {
			// for x86
			return (reinterpret_cast<Ret(*)(uint32_t, Args...)>(&impl::_syscall))(index, args...);
		}
	}

	template <typename Ret = long, typename ...Args>
	Ret call(char const* const func_name, const Args ...args) {
		return call(index(func_name), args...);
	}
} // namespace mango::syscall