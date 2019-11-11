#include "../../include/epic/vmt_hook.h"

#include "../../include/epic/process.h"
#include "../../include/misc/logger.h"
#include "../../include/misc/error_codes.h"


namespace mango {
	// instance is the address of the class instance to be hooked
	void VmtHook::setup(const Process& process, const uintptr_t instance, const SetupOptions& options) {
		this->release();

		this->m_process = &process;
		this->m_options = options;
		this->m_instance = instance;

		// original vtable
		this->m_original_vtable = uintptr_t(process.is_64bit() ?
			process.read<uint64_t>(instance) :
			process.read<uint32_t>(instance));

		// if m_replace_table is true:
		// create a new table, copy contents and swap
		// else:
		// just write directly to the current vtable
		if (options.m_replace_table) {
			// attempt to calculate vtable size ourselves (not accurate)
			try {
				this->m_vtable_size = 0;

				// keep increasing m_vtable_size until nullptr
				if (process.is_64bit()) {
					while (process.read<uint64_t>(this->m_original_vtable + this->m_vtable_size))
						this->m_vtable_size += 0x8;
				} else {
					while (process.read<uint32_t>(this->m_original_vtable + this->m_vtable_size))
						this->m_vtable_size += 0x4;
				}
			} catch (FailedToReadMemory&) {}

			// if it's 0 then its not a virtual class lmao
			if (!this->m_vtable_size)
				throw InvalidVtableSize();

			// allocate a new vtable
			this->m_vtable = process.alloc_virt_mem(this->m_vtable_size + process.get_ptr_size());

			// copy the old values to the new table (and the rtti complete locator)
			const auto old_table_content = std::make_unique<uint8_t[]>(this->m_vtable_size + process.get_ptr_size());
			process.read(this->m_original_vtable - process.get_ptr_size(), old_table_content.get(), this->m_vtable_size + process.get_ptr_size());
			process.write(this->m_vtable, old_table_content.get(), this->m_vtable_size + process.get_ptr_size());
			this->m_vtable += process.get_ptr_size();

			// swap the tables
			this->m_process->is_64bit() ?
				this->m_process->write<uint64_t>(this->m_instance, uint64_t(this->m_vtable)) :
				this->m_process->write<uint32_t>(this->m_instance, uint32_t(this->m_vtable));
		} else {
			this->m_vtable = this->m_original_vtable;
		}
	}

	// unhooks all functions
	void VmtHook::release() {
		if (!this->m_process || !this->m_vtable)
			return;

		// restore
		if (this->m_options.m_replace_table) {
			// no need to manually unhook every function since we can just replace the table
			this->m_process->is_64bit() ?
				this->m_process->write<uint64_t>(this->m_instance, uint64_t(this->m_original_vtable)) :
				this->m_process->write<uint32_t>(this->m_instance, uint32_t(this->m_original_vtable));

			// free the vtable that we allocated
			this->m_process->free_virt_mem(this->m_vtable - this->m_process->get_ptr_size());
		} else {
			// unhook all hooked functions
			for (const auto& [index, addr] : this->m_original_funcs)
				this->hook_internal(index, addr);
		}

		// reset
		this->m_original_funcs.clear();
		this->m_process = nullptr;
		this->m_instance = 0;
		this->m_vtable = 0;
		this->m_original_vtable = 0;
		this->m_vtable_size = 0;
	}

	// hook a function at the specified index (returns the original)
	uintptr_t VmtHook::hook(const size_t index, const uintptr_t func) {
		// if function already hooked
		if (this->m_original_funcs.find(index) != this->m_original_funcs.end())
			throw FunctionAlreadyHooked();

		const auto original = this->hook_internal(index, func);
		if (original) 
			return this->m_original_funcs[index] = original;

		// not sure how this would ever be reached
		return 0;
	}

	// unhook a previously hooked function
	void VmtHook::unhook(const size_t index) {
		if (const auto it = this->m_original_funcs.find(index); it != this->m_original_funcs.end()) {
			this->hook_internal(index, it->second);
			this->m_original_funcs.erase(it);
		}
	}

	// does all the heavy lifting
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