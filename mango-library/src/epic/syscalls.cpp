#include "../../include/epic/syscalls.h"

#include "../../include/misc/error_codes.h"
#include "../../include/crypto/string_encryption.h"

#include <Windows.h>


namespace mango {
	// same as ntdll.dll:Wow64Transition
	// might only work for windows 10 but can easily be fixed
	inline constexpr uint64_t x64_transition = 0x00000033'77796009;

	// dynamically get the sycall index of a function in ntdll.dll
	uint32_t syscall_index(const std::string& func_name) {
		static const auto ntdll_handle = GetModuleHandle(enc_str("ntdll.dll").c_str());

		// get the function address
		const auto func_addr = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll_handle, func_name.c_str()));
		if (!func_addr)
			throw FailedToGetFunctionAddress();

		// read the syscall index from the mov eax instruction
		if constexpr (sizeof(void*) == 8)
			return *reinterpret_cast<uint32_t*>(func_addr + 4);
		else
			return *reinterpret_cast<uint32_t*>(func_addr + 1);
	}

	// get address of Wow64Transition
	uint32_t get_x64transition() {
		if constexpr (sizeof(void*) == 8)
			return 0;

		const auto address = GetProcAddress(GetModuleHandle(
			enc_str("ntdll.dll").c_str()), enc_str("Wow64Transition").c_str());
		return *reinterpret_cast<uint32_t*>(address);
	}

	// verify that our hardcoded transition address is correct
	bool verify_x64transition() {
		if constexpr (sizeof(void*) == 8)
			return true;
		return get_x64transition() + 9 == uint32_t(x64_transition);
	}

#ifndef _WIN64
	// for syscalls in WOW64, basically just switch execution to 64bit mode and 
	// far jmp to x64 code that then executes a syscall in native code

	// no need for external .asm file since we can use inline asm in x86
	// TODO: manually use our own x64 syscall so we dont need to rely on Wow64Transition
	// + would probably work with most versions of windows too
	void __declspec(naked) _syscall_stub() {
		__asm {
			pop edx   // pop the return address into edx
			pop eax   // pop the syscall index into eax
			push edx  // push the return address back on the stack,

			// x64_address is a function but we jmp to it, so manually push the return address again
			push edx
			jmp fword ptr x64_transition
		}
	}
#endif
} // namespace mango