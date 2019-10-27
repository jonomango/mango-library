#include "../../include/epic/syscalls.h"

#include "../../include/misc/error_codes.h"
#include "../../include/crypto/string_encryption.h"

#include <Windows.h>


namespace mango {
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

#ifndef _WIN64
	// for syscalls in WOW64, basically just switch execution to 64bit mode and 
	// far jmp to x64 code that then executes a syscall in native code

	// same as ntdll.dll:Wow64Transition
	static constexpr uint64_t x64_address = 0x00000033'77796009; // 33:77796009

	// no need for external .asm file since we can use inline asm in x86
	void __declspec(naked) _syscall_stub() {
		__asm {
			pop edx   // pop the return address into edx
			pop eax   // pop the syscall index into eax
			push edx  // push the return address back on the stack,

			// x64_address is a function but we jmp to it, so manually push the return address again
			push edx
			jmp fword ptr x64_address
		}
	}
#endif
} // namespace mango