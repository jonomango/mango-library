#include "../../include/epic/hardware_breakpoint.h"


namespace {
	using namespace mango;
	using namespace mango::hwbp;

	template <bool is64bit>
	using Context = std::conditional_t<is64bit, CONTEXT, WOW64_CONTEXT>;

	// helper function to abstract away x64/x86 thread stuff
	template <bool is64bit>
	auto get_thread_context(const HANDLE thread) {
		// return type for this function depends on the template param
		Context<is64bit> context{ .ContextFlags = is64bit ? CONTEXT_DEBUG_REGISTERS : WOW64_CONTEXT_DEBUG_REGISTERS };

		// GetThreadContext() vs Wow64GetThreadContext()
		if constexpr (is64bit) {
			if (!GetThreadContext(thread, &context))
				throw FailedToGetThreadContext(mango_format_w32status(GetLastError()));
		} else {
			if (!Wow64GetThreadContext(thread, &context))
				throw FailedToGetThreadContext(mango_format_w32status(GetLastError()));
		}

		return context;
	}

	// helper function to abstract away x64/x86 thread stuff
	template <bool is64bit>
	void set_thread_context(const HANDLE thread, const Context<is64bit>& context) {
		// SetThreadContext() vs Wow64SetThreadContext()
		if constexpr (is64bit) {
			if (!SetThreadContext(thread, &context))
				throw FailedToSetThreadContext(mango_format_w32status(GetLastError()));
		} else {
			if (!Wow64SetThreadContext(thread, &context))
				throw FailedToSetThreadContext(mango_format_w32status(GetLastError()));
		}
	}

	// this is needed for cross-architecture support
	template <bool is64bit>
	void set_hwbp(const HANDLE thread, const uintptr_t address, const Options& options) {
		// https://en.wikipedia.org/wiki/X86_debug_register

		// get the thread context
		auto context(get_thread_context<is64bit>(thread));

		// enable the debug register, or crash if none available
		enable(context, address, options);

		// set our modified thread context
		return set_thread_context<is64bit>(thread, context);
	}
} // namespace

namespace mango::hwbp {
	// set a hardware breakpoint using one of the 4 debug registers
	// will throw an exception if all registers are used
	void enable(const Process& process, const HANDLE thread,
		const uintptr_t address, const Options& options) {

		// dont you just love abstractions?
		process.is_64bit() ?
			set_hwbp<true>(thread, address, options) :
			set_hwbp<false>(thread, address, options);
	}
} // namespace mango::hwbp