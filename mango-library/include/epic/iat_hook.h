#pragma once

#include <string>
#include <unordered_map>

#include "loaded_module.h"


namespace mango {
	class Process;

	// a bit of overhead but whatever
	// module names are case insensitive but not function names
	class IatHook {
	private:
		using HookedFuncs = std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>>;

	public:
		IatHook() = default;
		IatHook(const Process& process, const uintptr_t module_address) { this->setup(process, module_address); }
		IatHook(const Process& process, const void* const module_address) { this->setup(process, module_address); }
		~IatHook() { this->release(); }

		// all hooks will only affect the specified module
		void setup(const Process& process, const uintptr_t module_address);
		void setup(const Process& process, const void* const module_address) {
			this->setup(process, uintptr_t(module_address));
		}
		
		// unhooks everything
		void release();

		// same as setup() return value
		bool is_valid() const noexcept { return this->m_process != nullptr; }

		// hook a function
		uintptr_t hook(std::string module_name, const std::string& func_name, const uintptr_t func);

		// wrapper
		template <typename Ret = uintptr_t, typename Addr = uintptr_t>
		Ret hook(const std::string& module_name, const std::string& func_name, const Addr func) {
			return Ret(hook(module_name, func_name, uintptr_t(func)));
		}

		// unhook
		void unhook(std::string module_name, const std::string& func_name);

		// a more intuitive way to test for validity
		explicit operator bool() const noexcept { return this->is_valid(); }

		// prevent copying
		IatHook(const IatHook&) = delete;
		IatHook& operator=(const IatHook&) = delete;

	private:
		// this does all the heavy lifting
		uintptr_t hook_internal(const std::string& module_name, const std::string& func_name, const uintptr_t func);

	private:
		const Process* m_process = nullptr;
		HookedFuncs m_hooked_funcs;
		LoadedModule::ImportedFuncs m_iat;
	};
} // namespace mango