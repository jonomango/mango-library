#pragma once

#include <unordered_map>


namespace mango {
	class Process;

	// manages all hooks for a specific instance
	class VmtHook {
	private:
		using OriginalFuncs = std::unordered_map<size_t, uintptr_t>;

	public:
		struct SetupOptions {
			// to note, if you don't replace the table you will be hooking the function for EVERY instance of the class
			// while replacing the table will only hook for this specific instance.
			bool m_replace_table = true;

			// whether we should call release in the destructor or not
			bool m_auto_release = true;
		};

	public:
		VmtHook() = default;
		VmtHook(const Process& process, const uintptr_t instance, const SetupOptions& options = SetupOptions()) {
			this->setup(process, instance, options); 
		}
		VmtHook(const Process& process, const void* const instance, const SetupOptions& options = SetupOptions()) { 
			this->setup(process, instance, options); 
		}
		~VmtHook() {
			if (this->m_options.m_auto_release)
				this->release(); 
		}

		// instance is the address of the class instance to be hooked
		void setup(const Process& process, const uintptr_t instance, const SetupOptions& options = SetupOptions());
		void setup(const Process& process, const void* const instance, const SetupOptions& options = SetupOptions()) {
			this->setup(process, uintptr_t(instance), options);
		}

		// unhooks all functions
		void release();

		// hook a function at the specified index (returns the original)
		uintptr_t hook(const size_t index, const uintptr_t func);

		// wrapper
		template <typename Ret = uintptr_t, typename Addr = uintptr_t>
		Ret hook(const size_t index, const Addr func) {
			return Ret(this->hook(index, uintptr_t(func)));
		}

		// unhook a previously hooked function
		void unhook(const size_t index);

		// same as setup() return value
		bool is_valid() const noexcept { return this->m_process != nullptr; }

		// a more intuitive way to test for validity
		explicit operator bool() const noexcept { return this->is_valid(); }

		// prevent copying
		VmtHook(const VmtHook&) = delete;
		VmtHook& operator=(const VmtHook&) = delete;

	private:
		// does all the heavy lifting
		uintptr_t hook_internal(const size_t index, const uintptr_t func);

	private:
		const Process* m_process = nullptr; // this is kinda poopoo
		OriginalFuncs m_original_funcs;
		SetupOptions m_options;
		uintptr_t m_instance = 0,
			m_vtable = 0,
			m_original_vtable = 0;
		size_t m_vtable_size = 0;
	};
} // namespace mango