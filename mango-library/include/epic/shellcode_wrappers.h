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

	// shellcode for a vectored exception handler that will execute a callback when 
	// a single step exception is raised and the instruction pointer equals hookaddress
	// callback prototype: 
	//     void __fastcall callback(PEXCEPTION_POINTERS)
	template <bool is64bit>
	constexpr auto debug_register_veh(const mango::PtrType<is64bit> hookaddress, const mango::PtrType<is64bit> callback) noexcept {
		if constexpr (is64bit) {
			return std::array<uint8_t, 74>{
				0x48ui8, 0x8Bui8, 0x01ui8, 0x81ui8, 0x38ui8, 0x04ui8, 0x00ui8, 0x00ui8,
				0x80ui8, 0x75ui8, 0x39ui8, 0x48ui8, 0x8Bui8, 0x41ui8, 0x08ui8, 0x48ui8,
				0xBAui8,

				// hookaddress
				uint8_t(hookaddress >> 0), uint8_t(hookaddress >> 8),
				uint8_t(hookaddress >> 16), uint8_t(hookaddress >> 24),
				uint8_t(hookaddress >> 32), uint8_t(hookaddress >> 40),
				uint8_t(hookaddress >> 48), uint8_t(hookaddress >> 56),

				0x48ui8, 0x39ui8, 0x90ui8, 0xF8ui8, 0x00ui8, 0x00ui8, 0x00ui8, 0x75ui8,
				0x22ui8, 0x81ui8, 0x48ui8, 0x44ui8, 0x00ui8, 0x00ui8, 0x01ui8, 0x00ui8,
				0x48ui8, 0x83ui8, 0xECui8, 0x28ui8, 0x48ui8, 0xB8ui8,

				// callback
				uint8_t(callback >> 0), uint8_t(callback >> 8),
				uint8_t(callback >> 16), uint8_t(callback >> 24),
				uint8_t(callback >> 32), uint8_t(callback >> 40),
				uint8_t(callback >> 48), uint8_t(callback >> 56),

				0xFFui8, 0xD0ui8, 0x48ui8, 0x83ui8, 0xC4ui8, 0x28ui8, 0xB8ui8, 0xFFui8,
				0xFFui8, 0xFFui8, 0xFFui8, 0xEBui8, 0x05ui8, 0xB8ui8, 0x00ui8, 0x00ui8,
				0x00ui8, 0x00ui8, 0xC3ui8
			};
		} else {
			return std::array<uint8_t, 66>{
				0x55ui8, 0x89ui8, 0xE5ui8, 0x8Bui8, 0x4Dui8, 0x08ui8, 0x8Bui8, 0x19ui8,
				0x81ui8, 0x3Bui8, 0x04ui8, 0x00ui8, 0x00ui8, 0x80ui8, 0x75ui8, 0x2Aui8,
				0x8Bui8, 0x59ui8, 0x04ui8, 0x81ui8, 0xBBui8, 0xB8ui8, 0x00ui8, 0x00ui8,
				0x00ui8,

				// hookaddress
				uint8_t(hookaddress >> 0), uint8_t(hookaddress >> 8),
				uint8_t(hookaddress >> 16), uint8_t(hookaddress >> 24),

				0x75ui8, 0x1Bui8, 0x81ui8, 0x8Bui8, 0xC0ui8, 0x00ui8, 0x00ui8, 0x00ui8,
				0x00ui8, 0x00ui8, 0x01ui8, 0x00ui8, 0xB8ui8,

				// callback
				uint8_t(callback >> 0), uint8_t(callback >> 8),
				uint8_t(callback >> 16), uint8_t(callback >> 24),

				0xFFui8, 0xD0ui8, 0xB8ui8, 0xFFui8, 0xFFui8, 0xFFui8, 0xFFui8, 0xEBui8,
				0x05ui8, 0xB8ui8, 0x00ui8, 0x00ui8, 0x00ui8, 0x00ui8, 0x89ui8, 0xECui8,
				0x5Dui8, 0xC2ui8, 0x04ui8, 0x00ui8
			};
		}
	}
} // namespace mango::shw