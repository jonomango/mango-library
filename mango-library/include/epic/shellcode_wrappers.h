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
	// X64:
	//     push rbp
	//     mov rbp, rsp
	// X86:
	//     push ebp
	//     mov ebp, esp
	template <bool is64bit>
	constexpr StringWrapper prologue() noexcept {
		if constexpr (is64bit) {
			return "\x55\x48\x89\xE5";
		} else {
			return "\x55\x89\xE5";
		}
	}

	// end a stackframe:
	// X64:
	//     mov rsp, rbp
	//     pop rbp
	// X86:
	//     mov esp, ebp
	//     pop ebp
	template <bool is64bit>
	constexpr StringWrapper epilogue() noexcept {
		if constexpr (is64bit) {
			return "\x48\x89\xEC\x5D";
		} else {
			return "\x89\xEC\x5D";
		}
	}

	// switch execution to 64 bit mode
	// X86:
	//     push 0x33 (0x33 = x64 code segment)
	//     call +0x5
	//     add dword ptr [esp], 0x5
	//     retf
	constexpr StringWrapper enter64bit() noexcept {
		return "\x6A\x33"
			"\xE8\x00\x00\x00\x00"
			"\x83\x04\x24\x05"
			"\xCB";
	}

	// switch execution to 32 bit mode
	// X86:
	//     call +0x5
	//     mov dword ptr [rsp + 4], 0x23 (0x23 = x86 code segment)
	//     add qword ptr [rsp], 0x0E
	//     retf
	constexpr StringWrapper enter32bit() noexcept {
		return "\xE8\x00\x00\x00\x00"
			"\xC7\x44\x24\x04\x23\x00\x00\x00"
			"\x48\x83\x04\x24\x0E"
			"\xCB";
	}

	// basically just performs a jmp to address
	// X86:
	//     push address
	//     ret
	// X64:
	//     push (address & 0xFFFFFFFF)
	//     mov dword ptr [rsp + 4], (address >> 32)
	//     ret
	template <bool is64bit>
	constexpr auto absjmp(const PtrType<is64bit> address) noexcept {
		if constexpr (is64bit) {
			return std::array<uint8_t, 14>{
				0x68, 
				uint8_t(address >> 0), uint8_t(address >> 8), 
				uint8_t(address >> 16), uint8_t(address >> 24),
				0xC7, 0x44, 0x24, 0x04, 
				uint8_t(address >> 32), uint8_t(address >> 40),
				uint8_t(address >> 48), uint8_t(address >> 56),
				0xC3
			};
		} else {
			return std::array<uint8_t, 6>{
				0x68, 
				uint8_t(address >> 0), uint8_t(address >> 8),
				uint8_t(address >> 16), uint8_t(address >> 24),
				0xC3
			};
		}
	}

	// shellcode for a vectored exception handler that will execute a callback when 
	// a single step exception is raised and the instruction pointer equals hookaddress
	// callback prototype: 
	//     void __fastcall callback(PEXCEPTION_POINTERS)
	template <bool is64bit>
	constexpr auto debug_register_veh(const PtrType<is64bit> hookaddress, const PtrType<is64bit> callback) noexcept {
		if constexpr (is64bit) {
			return std::array<uint8_t, 74>{
				0x48, 0x8B, 0x01, 0x81, 0x38, 0x04, 0x00, 0x00,
				0x80, 0x75, 0x39, 0x48, 0x8B, 0x41, 0x08, 0x48,
				0xBA,

				// hookaddress
				uint8_t(hookaddress >> 0), uint8_t(hookaddress >> 8),
				uint8_t(hookaddress >> 16), uint8_t(hookaddress >> 24),
				uint8_t(hookaddress >> 32), uint8_t(hookaddress >> 40),
				uint8_t(hookaddress >> 48), uint8_t(hookaddress >> 56),

				0x48, 0x39, 0x90, 0xF8, 0x00, 0x00, 0x00, 0x75,
				0x22, 0x81, 0x48, 0x44, 0x00, 0x00, 0x01, 0x00,
				0x48, 0x83, 0xEC, 0x28, 0x48, 0xB8,

				// callback
				uint8_t(callback >> 0), uint8_t(callback >> 8),
				uint8_t(callback >> 16), uint8_t(callback >> 24),
				uint8_t(callback >> 32), uint8_t(callback >> 40),
				uint8_t(callback >> 48), uint8_t(callback >> 56),

				0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xB8, 0xFF,
				0xFF, 0xFF, 0xFF, 0xEB, 0x05, 0xB8, 0x00, 0x00,
				0x00, 0x00, 0xC3
			};
		} else {
			return std::array<uint8_t, 66>{
				0x55, 0x89, 0xE5, 0x8B, 0x4D, 0x08, 0x8B, 0x19,
				0x81, 0x3B, 0x04, 0x00, 0x00, 0x80, 0x75, 0x2A,
				0x8B, 0x59, 0x04, 0x81, 0xBB, 0xB8, 0x00, 0x00,
				0x00,

				// hookaddress
				uint8_t(hookaddress >> 0), uint8_t(hookaddress >> 8),
				uint8_t(hookaddress >> 16), uint8_t(hookaddress >> 24),

				0x75, 0x1B, 0x81, 0x8B, 0xC0, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x01, 0x00, 0xB8,

				// callback
				uint8_t(callback >> 0), uint8_t(callback >> 8),
				uint8_t(callback >> 16), uint8_t(callback >> 24),

				0xFF, 0xD0, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xEB,
				0x05, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x89, 0xEC,
				0x5D, 0xC2, 0x04, 0x00
			};
		}
	}
} // namespace mango::shw