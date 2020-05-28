#pragma once

#include "process.h"


namespace mango {
	// get the address of a virtual method in an instance
	template <typename Ret, typename Addr>
	Ret get_vfunc(const Process& process, const Addr instance, const size_t index) {
		uintptr_t address = 0;
		if (process.is_64bit())
			address = process.read<uintptr_t>(process.read<uintptr_t>(instance) + sizeof(uintptr_t) * index);
		else
			address = process.read<uint32_t>(process.read<uint32_t>(instance) + sizeof(uint32_t) * index);
		return (Ret)address;
	}

	// only to be used when in same memory-space
	template <typename Ret, typename... Args>
	Ret call_vfunc(const size_t index, const void* const instance, const Args ...args) {
		using fn = Ret(__thiscall*)(const void*, Args...);
		return ((*reinterpret_cast<fn* const*>(instance))[index])(instance, args...);
	}
} // namespace mango