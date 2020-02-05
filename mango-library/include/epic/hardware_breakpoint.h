#pragma once

#include "thread.h"
#include "process.h"
#include "windows_defs.h"
#include "../misc/error_codes.h"


// https://en.wikipedia.org/wiki/X86_debug_register
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

	namespace impl {
		// sets up DR7 for our use (or throws) and returns which dbg register was used
		size_t enable_DR7(uint32_t& DR7, const Options& options);

		// clears out the control settings for that debug register
		void clear_dreg(uint32_t& DR7, const size_t index);
	} // namespace impl

	// check if a debug register is currently enabled
	bool is_enabled(const uint32_t DR7, const size_t index);

	// set a hardware breakpoint using one of the 4 debug registers
	// will throw an exception if all registers are used
	// safe to use on current thread (although technically "undefined behavior")
	void enable(const Process& process, const HANDLE thread, 
		const uintptr_t address, const Options& options = Options{});
	inline void enable(const Process& process, const Thread& thread,
		const uintptr_t address, const Options& options = Options{}) 
	{
		enable(process, thread.get_handle(), address, options);
	}

	// Ctx must be either CONTEXT or WOW64_CONTEXT
	template <typename Ctx>
	void enable(Ctx& context, const uintptr_t address, const Options& options = Options{}) {
		auto DR7(uint32_t(context.Dr7));
		(&context.Dr0)[impl::enable_DR7(DR7, options)] = 
			static_cast<decltype(context.Dr0)>(address);
		context.Dr7 = DR7;
	}

	// disable all hardware breakpoint in specified thread that have a value of specified address
	void disable(const Process& process, const HANDLE thread, const uintptr_t address);
	inline void disable(const Process& process, const Thread& thread, const uintptr_t address) {
		disable(process, thread.get_handle(), address);
	}

	// Ctx must be either CONTEXT or WOW64_CONTEXT
	template <typename Ctx>
	void disable(Ctx& context, const uintptr_t address) {
		auto DR7(uint32_t(context.Dr7));

		for (size_t i(0); i < 4; ++i) {
			if (!is_enabled(DR7, i))
				continue;

			// debug register doesn't point to our address, ignore
			if ((&context.Dr0)[i] != address)
				continue;

			impl::clear_dreg(DR7, i);
			(&context.Dr0)[i] = 0;
		}

		context.Dr7 = DR7;
	}
} // namespace mango::hwbp