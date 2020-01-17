#pragma once

#include "../misc/misc.h"

#include <array>


// commonly used shellcode snippets go here
namespace mango::shw {
	// ret or retn instruction
	constexpr StringWrapper ret() noexcept { return "\xC3"; }
	constexpr std::array<uint8_t, 3> ret(const uint16_t size) noexcept {
		return { uint8_t(0xC2), uint8_t(size), uint8_t(size >> 8) };
	}

	// start a stackframe:
	//
	// X64:
	// push rbp
	// mov rbp, rsp
	//
	// X86:
	// push ebp
	// mov ebp, esp
	template <bool is64bit>
	constexpr StringWrapper prologue() noexcept {
		if constexpr (is64bit) {
			return "\x55\x48\x89\xE5";
		} else {
			return "\x55\x89\xE5";
		}
	}

	// end a stackframe:
	//
	// X64:
	// mov rsp, rbp
	// pop rbp
	//
	// X86:
	// mov esp, ebp
	// pop ebp
	template <bool is64bit>
	constexpr StringWrapper epilogue() noexcept {
		if constexpr (is64bit) {
			return "\x48\x89\xEC\x5D";
		} else {
			return "\x89\xEC\x5D";
		}
	}

	// switch execution to 64 bit mode
	//
	// X86:
	// push 0x33 (0x33 = x64 code segment)
	// call +0x5
	// add dword ptr [esp], 0x5
	// retf
	constexpr StringWrapper enter64bit() noexcept {
		return "\x6A\x33"
			"\xE8\x00\x00\x00\x00"
			"\x83\x04\x24\x05"
			"\xCB";
	}

	// switch execution to 32 bit mode
	//
	// X86:
	// call +0x5
	// mov dword ptr [rsp + 4], 0x23 (0x23 = x86 code segment)
	// add qword ptr [rsp], 0x0E
	// retf
	constexpr StringWrapper enter32bit() noexcept {
		return "\xE8\x00\x00\x00\x00"
			"\xC7\x44\x24\x04\x23\x00\x00\x00"
			"\x48\x83\x04\x24\x0E"
			"\xCB";
	}
} // namespace mango::shw