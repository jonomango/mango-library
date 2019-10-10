#pragma once

#include <string>
#include <unordered_map>

#include <epic/pe_header.h>


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
		bool setup(const Process& process, const uintptr_t module_address);
		bool setup(const Process& process, const void* const module_address) {
			return this->setup(process, uintptr_t(module_address));
		}
		
		// unhooks everything
		void release();

		// hook a function
		uintptr_t hook(std::string module_name, const std::string& func_name, const uintptr_t func);

		template <typename T = uintptr_t, typename C = uintptr_t>
		T hook(const std::string& module_name, const std::string& func_name, C const func) {
			return T(hook(module_name, func_name, uintptr_t(func)));
		}

		// unhook
		void unhook(std::string module_name, const std::string& func_name);

		// same as setup() return value
		bool is_valid() const { return this->m_process != nullptr; }

		// a more intuitive way to test for validity
		explicit operator bool() const { return this->is_valid(); }

		// prevent copying
		IatHook(const IatHook&) = delete;
		IatHook& operator=(const IatHook&) = delete;

	private:
		// unhook also uses this
		uintptr_t hook_internal(const std::string& module_name, const std::string& func_name, const uintptr_t func);

	private:
		const Process* m_process = nullptr;
		HookedFuncs m_hooked_funcs;
		PeHeader::ImportedFuncs m_iat;
	};
} // namespace mango