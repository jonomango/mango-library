#include "../../include/epic/iat_hook.h"

#include <algorithm>

#include "../../include/epic/process.h"
#include "../../include/misc/logger.h"
#include "../../include/misc/error_codes.h"


namespace mango {
	// all hooks will only affect the specified module
	void IatHook::setup(const Process& process, const uintptr_t module_address) {
		this->release();

		// parse pe header
		if (const auto pe_header = LoadedModule(process, module_address); pe_header) {
			this->m_iat = pe_header.get_imports();
			this->m_process = &process;
		}
	}

	// unhooks everything
	void IatHook::release() {
		if (!this->m_process)
			return;

		// unhook every function
		for (const auto& [module_name, funcs] : this->m_hooked_funcs)
			for (const auto& [func_name, address] : funcs)
				this->hook_internal(module_name, func_name, address);

		this->m_hooked_funcs.clear();
		this->m_process = nullptr;
	}

	// hook a function
	uintptr_t IatHook::hook(std::string module_name, const std::string& func_name, const uintptr_t func) {
		// change module name to lowercase
		std::transform(module_name.begin(), module_name.end(), module_name.begin(), std::tolower);

		// make sure not hooked already
		if (const auto& functions = this->m_hooked_funcs.find(module_name); functions != this->m_hooked_funcs.end()) {
			if (functions->second.find(func_name) != functions->second.end())
				throw FunctionAlreadyHooked();
		}

		// hook
		const auto original = this->hook_internal(module_name, func_name, func);
		if (original)
			return (this->m_hooked_funcs[module_name][func_name] = original);
		return 0;
	}

	// unhook
	void IatHook::unhook(std::string module_name, const std::string& func_name) {
		// change module name to lowercase
		std::transform(module_name.begin(), module_name.end(), module_name.begin(), std::tolower);

		const auto& functions = this->m_hooked_funcs.find(module_name);
		if (functions == this->m_hooked_funcs.end()) // not hooked
			return;

		const auto& func = functions->second.find(func_name);
		if (func == functions->second.end()) // not hooked
			return;

		// unhook
		if (this->hook_internal(module_name, func_name, func->second))
			functions->second.erase(func);
	}

	// this does all the heavy lifting
	uintptr_t IatHook::hook_internal(const std::string& module_name, const std::string& func_name, const uintptr_t func) {
		const auto it = this->m_iat.find(module_name);
		if (it == this->m_iat.end())
			throw FailedToFindImportModule();

		const auto entry = it->second.find(func_name);
		if (entry == it->second.end())
			throw FailedToFindImportFunction();

		// the address of where the virtual function is
		const auto address = entry->second.m_table_address;

		if (this->m_process->is_64bit()) {
			// set page protection to allow writing
			const auto old_prot = this->m_process->set_mem_prot(address, sizeof(uint64_t), PAGE_READWRITE);

			// overwrite
			this->m_process->write<uint64_t>(address, func);

			// restore page protection to old value
			this->m_process->set_mem_prot(address, sizeof(uint64_t), old_prot);
		} else {
			// set page protection to allow writing
			const auto old_prot = this->m_process->set_mem_prot(address, sizeof(uint32_t), PAGE_READWRITE);

			// overwrite
			this->m_process->write<uint32_t>(address, uint32_t(func));

			// restore page protection to old value
			this->m_process->set_mem_prot(address, sizeof(uint32_t), old_prot);
		}

		// return original
		return entry->second.m_address;
	}
} // namespace mango