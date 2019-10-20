#pragma once

#include <unordered_map>


namespace mango {
	class Process;

	// manages all hooks for a specific instance
	class VmtHook {
	private:
		using OriginalFuncs = std::unordered_map<size_t, uintptr_t>;

	public:
		VmtHook() = default;
		VmtHook(const Process& process, const uintptr_t instance) { this->setup(process, instance); }
		VmtHook(const Process& process, const void* const instance) { this->setup(process, instance); }
		~VmtHook() { this->release(); }

		// instance is the address of the class instance to be hooked
		void setup(const Process& process, const uintptr_t instance);
		void setup(const Process& process, const void* const instance) {
			this->setup(process, uintptr_t(instance));
		}

		// unhooks all functions
		void release();

		// hook a function at the specified index (returns the original)
		uintptr_t hook(const size_t index, const uintptr_t func);

		// wrapper
		template <typename Ret = uintptr_t, typename Addr = uintptr_t>
		Ret hook(const size_t index, Addr const func) {
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
		// unhook also uses this
		uintptr_t hook_internal(const size_t index, const uintptr_t func);

	private:
		const Process* m_process = nullptr; // this is kinda poopoo
		OriginalFuncs m_original_funcs;
		uintptr_t m_vtable = 0;
	};
} // namespace mango