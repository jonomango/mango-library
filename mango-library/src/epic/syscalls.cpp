#include "../../include/epic/syscalls.h"

#include "../../include/misc/error_codes.h"
#include "../../include/crypto/string_encryption.h"

#include <Windows.h>


namespace mango {
	// dynamically get the sycall index of a function in ntdll.dll
	uint32_t syscall_index(const std::string& func_name) {
		static const auto ntdll_handle{ GetModuleHandle(enc_str("ntdll.dll").c_str()) };

		// get the function address
		const auto func_addr{ reinterpret_cast<uint8_t*>(GetProcAddress(ntdll_handle, func_name.c_str())) };
		if (!func_addr)
			throw FailedToGetFunctionAddress{};

		// read the syscall index from the mov eax instruction
		if constexpr (sizeof(void*) == 8) {
			return *reinterpret_cast<uint32_t*>(func_addr + 4);
		} else {
			return *reinterpret_cast<uint32_t*>(func_addr + 1);
		}
	}

#ifndef _WIN64
	namespace impl {
		void __declspec(naked) _syscall() {
			__asm {
				pop edx   // pop the return address into edx
				pop eax   // pop the syscall index into eax
				push edx  // push the return address back on the stack

				// manually push the return address
				push edx

#pragma warning(suppress: 4410 4409)
				jmp fs : [0xC0]
			}
		}
	} // namespace impl
#endif
} // namespace mango