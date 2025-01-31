#pragma once

#include "loaded_module.h"
#include "process.h"

#include <string>
#include <unordered_map>


namespace mango {
	// a bit of overhead but whatever
	// module names are case insensitive but not function names
	class IatHook {
	private:
		using HookedFuncs = std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>>;

	public:
		struct SetupOptions {
			// whether we should call release in the destructor or not
			bool auto_release = true;
		};

	public:
		IatHook() = default;
		IatHook(const Process& process, const uintptr_t module_address, const SetupOptions& options = SetupOptions()) { this->setup(process, module_address, options); }
		IatHook(const Process& process, const void* const module_address, const SetupOptions& options = SetupOptions()) { this->setup(process, module_address, options); }
		~IatHook() {
			if (this->m_options.auto_release)
				this->release(); 
		}

		// all hooks will only affect the specified module
		void setup(const Process& process, const uintptr_t module_address, const SetupOptions& options = SetupOptions());
		void setup(const Process& process, const void* const module_address, const SetupOptions& options = SetupOptions()) {
			this->setup(process, uintptr_t(module_address), options);
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
		LoadedModule::ImportedFuncs m_iat;
		HookedFuncs m_hooked_funcs;
		SetupOptions m_options;
	};
} // namespace mango