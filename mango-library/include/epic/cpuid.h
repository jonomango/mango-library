#pragma once

#include <intrin.h>
#include <string>


namespace mango {
	// small cpuid instruction wrapper
	// https://en.wikipedia.org/wiki/CPUID
	struct Cpuid {
		explicit Cpuid(int function_id) {
			__cpuid(reinterpret_cast<int*>(this->registers), function_id);
		}

#pragma warning(push)
#pragma warning(disable : 4201) // warning C4201: nonstandard extension used: nameless struct/union
		union {
			uint32_t registers[4];
			struct {
				uint32_t eax, ebx, ecx, edx;
			};
		};
#pragma warning(pop)
	};

	// cpuid 0
	inline std::string cpu_manufacturer() {
		// read the string
		const Cpuid cpuid(0);
		
		// copy from registers
		std::string string(12, ' ');
		*reinterpret_cast<uint32_t*>(string.data()) = cpuid.ebx;
		*reinterpret_cast<uint32_t*>(string.data() + 4) = cpuid.edx;
		*reinterpret_cast<uint32_t*>(string.data() + 8) = cpuid.ecx;
		
		return string; 
	}
} // namespace mango