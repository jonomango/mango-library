#pragma once

#include <stdint.h>


namespace mango {
	class Process;
	class Shellcode;

	// Syscall hooks for Wow64 processes
	class Wow64SyscallHook {
	public:
		// return false to not call the original syscall
		using Callback = bool(*)(const uint32_t syscall_index, uint32_t* const arguments, volatile uint32_t return_value);

		struct SetupOptions {
			// whether we should call release in the constructor or not
			bool m_auto_release = true;
		};

	public:
		Wow64SyscallHook() = default;
		Wow64SyscallHook(const Process& process, const uint32_t callback, const SetupOptions& options = SetupOptions()) {
			this->hook(process, callback, options); 
		}

		// calls release()
		~Wow64SyscallHook() {
			if (this->m_options.m_auto_release)
				this->release(); 
		}

		// hooks
		void hook(const Process& process, const uint32_t callback, const SetupOptions& options = SetupOptions());

		// unhooks
		void release();

	private:
		// builds the function stub
		void build_shellcode(const uint32_t callback);

	private:
		const Process* m_process = nullptr;
		SetupOptions m_options;
		uint32_t wow64_transition = 0,
			m_original = 0,
			m_shellcode_addr = 0;
	};
} // namespace mango