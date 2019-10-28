#pragma once

#include <stdint.h>


namespace mango {
	class Process;
	class Shellcode;

	// Syscall hooks for Wow64 processes
	class Wow64SyscallHook {
	public:
		using PreCallback = void(*)(uint32_t index, uint32_t* stack);

		struct SetupOptions {
			// whether we should call release in the constructor or not
			bool m_auto_release = true;
		};

	public:
		Wow64SyscallHook() = default;
		Wow64SyscallHook(const Process& process, const uint32_t pre_callback, const SetupOptions& options = SetupOptions()) {
			this->hook(process, pre_callback, options); 
		}
		Wow64SyscallHook(const Process& process, const void* const pre_callback, const SetupOptions& options = SetupOptions()) {
			this->hook(process, pre_callback, options);
		}

		// calls release()
		~Wow64SyscallHook() {
			if (this->m_options.m_auto_release)
				this->release(); 
		}

		// hooks
		void hook(const Process& process, const uint32_t pre_callback, const SetupOptions& options = SetupOptions());
		void hook(const Process& process, const void* const pre_callback, const SetupOptions& options = SetupOptions()) {
			this->hook(process, uint32_t(pre_callback), options);
		}

		// unhooks
		void release();

	private:
		// builds the function stub
		void build_shellcode(const uint32_t address);

	private:
		const Process* m_process = nullptr;
		SetupOptions m_options;
		uint32_t wow64_transition = 0,
			m_original = 0,
			m_shellcode_addr = 0;
	};
} // namespace mango