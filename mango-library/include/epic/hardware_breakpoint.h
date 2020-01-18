#pragma once

#include "process.h"
#include "../misc/error_codes.h"

#include <Windows.h>


namespace mango::hwbp {
	enum class Type {
		execute   = 0b00,
		write     = 0b01,
		readwrite = 0b11
	};

	enum class Size {
		one   = 0b00,
		two   = 0b01,
		four  = 0b11,
		eight = 0b10
	};

	// default options are setup for setting breakpoints on code
	struct Options {
		// specifies when the bp will be triggered
		Type type = Type::execute;

		// the size, in bytes, of where the bp will trigger
		Size size = Size::one;
	};

	// set a hardware breakpoint using one of the 4 debug registers
	// will throw an exception if all registers are used
	void enable(const Process& process, const HANDLE thread, 
		const uintptr_t address, const Options& options = Options{});

	// Ctx must be either CONTEXT or WOW64_CONTEXT
	// TODO: sucks that this has to be templated and in the header file... maybe figure a solution and move to .cpp?
	template <typename Ctx>
	void enable(Ctx& context, const uintptr_t address, const Options& options = Options{}) {
		auto DR7(uint32_t(context.Dr7));

		// look for an unused debug register
		for (size_t i(0); i < 4; ++i) {
			const auto local_enable_mask(uint32_t(1) << (i * 2));

			// skip debug registers that are already being used
			if (DR7 & local_enable_mask)
				continue;

			// enable this debug register for our use
			DR7 |= local_enable_mask;
			(&context.Dr0)[i] = static_cast<decltype(context.Dr0)>(address); // annoying cast to fix warnings...

			// specify when the breakpoint should trigger
			DR7 &= ~uint32_t(0b11 << (16 + i * 4));      // clear value
			DR7 |= uint32_t(options.type) << (16 + i * 4); // set value

			// specify the breakpoint size
			DR7 &= ~(uint32_t(0b11) << (18 + i * 4));      // clear value
			DR7 |= uint32_t(options.size) << (18 + i * 4); // set value

			context.Dr7 = DR7;
			return;
		}

		// gg couldn't find a free debug register to use
		throw NoAvailableDebugRegisters{};
	}
} // namespace mango::hwbp