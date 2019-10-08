#pragma once

#include <unordered_map>


namespace mango {
	class Process;

	class VmtHook {
	private:
		// might change this
		using OriginalFuncs = std::unordered_map<size_t, uintptr_t>;

	public:
		VmtHook() = default;
		VmtHook(const Process& process, const uintptr_t instance) {
			this->setup(process, instance);
		}
		VmtHook(const Process& process, const void* const instance) {
			this->setup(process, uintptr_t(instance));
		}
		~VmtHook() {
			this->release();
		}

		// instance is the address of the class instance to be hooked
		void setup(const Process& process, const uintptr_t instance);
		void setup(const Process& process, const void* const instance) {
			this->setup(process, uintptr_t(instance));
		}

		// unhooks all functions
		void release();

		// hook a function at the specified index (returns the original)
		uintptr_t hook(const size_t index, const uintptr_t func);

		// small wrapper over this->hook()
		template <typename T = uintptr_t, typename C = uintptr_t>
		T hook(const size_t index, C const func) {
			return T(this->hook(index, uintptr_t(func)));
		}

		// unhook a previously hooked function
		void unhook(const size_t index);

	private:
		// unhook also uses this
		uintptr_t hook_internal(const size_t index, const uintptr_t func);

	private:
		const Process* m_process = nullptr; // this is kinda poopoo
		OriginalFuncs m_original_funcs;
		uintptr_t m_vtable = 0;
	};
} // namespace mango