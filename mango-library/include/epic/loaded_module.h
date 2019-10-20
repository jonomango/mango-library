#pragma once

#include <string>
#include <stdint.h>
#include <unordered_map>
#include <optional>


namespace mango {
	class Process;

	// copying is allowed
	class LoadedModule {
	public:
		struct PeEntry {
			uintptr_t m_address = 0,
				m_table_address = 0;
		};

		// EAT and IAT
		using ExportedFuncs = std::unordered_map<std::string /* func name */, PeEntry>;
		using ImportedFuncs = std::unordered_map<std::string /* module name */, 
			std::unordered_map<std::string /* func name */, PeEntry>>;

		template <bool>
		friend void setup_internal(LoadedModule* loaded_module, const Process& process, const uintptr_t address);

	public:
		LoadedModule() = default; // left in an invalid state
		LoadedModule(const Process& process, const void* const address) { this->setup(process, address); }
		LoadedModule(const Process& process, const uintptr_t address) { this->setup(process, address); }

		// setup (parse the pe header mostly)
		void setup(const Process& process, const uintptr_t address);
		void setup(const Process& process, const void* const address) {
			this->setup(process, uintptr_t(address));
		}

		// check if successfully parsed the pe header
		bool is_valid() const noexcept { return this->m_is_valid; }

		// image base (passed in constructor)
		uintptr_t get_image_base() const { return this->m_image_base; }

		// get the size of image
		size_t get_image_size() const { return this->m_image_size; }

		// get exported functions
		const ExportedFuncs& get_exports() const { return this->m_exported_funcs; }
		std::optional<PeEntry> get_export(const std::string func_name) const;

		// get imported functions
		const ImportedFuncs& get_imports() const { return this->m_imported_funcs; }
		std::optional<PeEntry> get_import(const std::string module_name, const std::string func_name) const;

		// a more intuitive way to test for validity
		explicit operator bool() const noexcept { return this->is_valid(); }

	private:
		bool m_is_valid = false;
		size_t m_image_size = 0;
		uintptr_t m_image_base = 0;
		ExportedFuncs m_exported_funcs;
		ImportedFuncs m_imported_funcs;
	};
} // namespace mango