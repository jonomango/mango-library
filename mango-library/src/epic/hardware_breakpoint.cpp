#include "../../include/epic/hardware_breakpoint.h"


namespace mango::hwbp {
	namespace impl {
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
			// get the thread context
			auto context(get_thread_context<is64bit>(thread));

			// enable the debug register, or crash if none available
			enable(context, address, options);

			// set our modified thread context
			set_thread_context<is64bit>(thread, context);
		}

		template <bool is64bit>
		void remove_hwbp(const HANDLE thread, const uintptr_t address) {
			// get the thread context
			auto context(get_thread_context<is64bit>(thread));

			// disable all debug registers with same address
			disable(context, address);

			// set our modified thread context
			set_thread_context<is64bit>(thread, context);
		}

		// sets up DR7 for our use (or throws) and returns which dbg register was used
		size_t enable_DR7(uint32_t& DR7, const Options& options) {
			// look for an unused debug register
			for (size_t i(0); i < 4; ++i) {
				if (is_enabled(DR7, i))
					continue;

				// enable this debug register for our use
				DR7 |= uint32_t(1) << (i * 2);

				// specify the breakpoint size and when it should trigger
				const auto type_size_mask((uint32_t(options.size) << 2) | uint32_t(options.type));
				DR7 &= ~uint32_t(0b1111 << (16 + i * 4)); // clear old value
				DR7 |= type_size_mask << (16 + i * 4);

				return i;
			}

			// gg couldn't find a free debug register to use
			throw NoAvailableDebugRegisters{};
		}

		// clears out the control settings for that debug register
		void clear_dreg(uint32_t& DR7, const size_t index) {
			// disable this debug register
			DR7 &= ~(uint32_t(1) << (index * 2));

			// clear out the size/type as well cuz we're nice people
			DR7 &= ~uint32_t(0b1111 << (16 + index * 4));
		}
	} // namespace impl

	// check if a debug register is currently enabled
	bool is_enabled(const uint32_t DR7, const size_t index) {
		return DR7 & (uint32_t(1) << (index * 2));
	}

	// set a hardware breakpoint using one of the 4 debug registers
	// will throw an exception if all registers are used
	// safe to use on current thread (although technically "undefined behavior")
	void enable(const Process& process, const HANDLE thread,
		const uintptr_t address, const Options& options) {

		// forward to actual implementation
		process.is_64bit() ?
			impl::set_hwbp<true>(thread, address, options) :
			impl::set_hwbp<false>(thread, address, options);
	}

	// disable all hardware breakpoint in specified thread that have a value of specified address
	void disable(const Process& process, const HANDLE thread, const uintptr_t address) {
		// forward to actual implementation
		process.is_64bit() ?
			impl::remove_hwbp<true>(thread, address) :
			impl::remove_hwbp<false>(thread, address);
	}
} // namespace mango::hwbp