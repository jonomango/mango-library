#include <epic/vmt_hook.h>

#include <epic/process.h>


namespace mango {
	// instance is the address of the class instance to be hooked
	void VmtHook::setup(const Process& process, const uintptr_t instance) {
		this->m_process = &process;

		// void**
		this->m_vtable = uintptr_t(process.is_64bit() ?
			process.read<uint64_t>(instance) :
			process.read<uint32_t>(instance));
	}

	// unhooks all functions
	void VmtHook::release() {
		if (!this->m_process || !this->m_vtable)
			return;

		// unhook all hooked functions
		for (const auto& [index, addr] : this->m_original_funcs)
			this->hook_internal(index, addr);
		this->m_original_funcs.clear();

		this->m_process = nullptr;
		this->m_vtable = 0;
	}

	// hook a function at the specified index (returns the original)
	uintptr_t VmtHook::hook(const size_t index, const uintptr_t func) {
		const auto original = this->hook_internal(index, func);
		return this->m_original_funcs[index] = original;
	}

	// unhook a previously hooked function
	void VmtHook::unhook(const size_t index) {
		if (const auto it = this->m_original_funcs.find(index); it != this->m_original_funcs.end()) {
			this->hook_internal(index, it->second);
			this->m_original_funcs.erase(it);
		}
	}

	uintptr_t VmtHook::hook_internal(const size_t index, const uintptr_t func) {
		if (this->m_process->is_64bit()) {
			// the address of where the virtual function is
			const auto address = this->m_vtable + sizeof(uint64_t) * index;

			// set page protection to allow writing
			const auto old_prot = this->m_process->set_mem_prot(address, sizeof(uint64_t), PAGE_READWRITE);

			// remember the old value, then overwrite it
			const auto original = this->m_process->read<uint64_t>(address);
			this->m_process->write<uint64_t>(address, func);

			// restore page protection to old value
			this->m_process->set_mem_prot(address, sizeof(uint64_t), old_prot);

			return uintptr_t(original);
		} else {
			// the address of where the virtual function is
			const auto address = this->m_vtable + sizeof(uint32_t) * index;

			// set page protection to allow writing
			const auto old_prot = this->m_process->set_mem_prot(address, sizeof(uint32_t), PAGE_READWRITE);

			// remember the old value, then overwrite it
			const auto original = this->m_process->read<uint32_t>(address);
			this->m_process->write<uint32_t>(address, uint32_t(func));

			// restore page protection to old value
			this->m_process->set_mem_prot(address, sizeof(uint32_t), old_prot);

			return uintptr_t(original);
		}
	}
} // namespace mango