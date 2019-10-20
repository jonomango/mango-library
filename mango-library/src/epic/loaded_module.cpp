#include "../../include/epic/loaded_module.h"

#include <iostream>
#include <algorithm>

#include "../../include/epic/process.h"
#include "../../include/misc/error_codes.h"


namespace mango {
	template <bool is64bit>
	void setup_internal(LoadedModule* loaded_module, const Process& process, const uintptr_t address) {
		// architecture dependent types
		using image_nt_headers = typename std::conditional<is64bit, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32>::type;
		using image_optional_header = typename std::conditional<is64bit, IMAGE_OPTIONAL_HEADER64, IMAGE_OPTIONAL_HEADER32>::type;
		using image_thunk_data = typename std::conditional<is64bit, IMAGE_THUNK_DATA64, IMAGE_THUNK_DATA32>::type;

		const auto dos_header = process.read<IMAGE_DOS_HEADER>(address);
		const auto nt_header = process.read<image_nt_headers>(address + dos_header.e_lfanew);

		// not a PE signature
		if (nt_header.Signature != IMAGE_NT_SIGNATURE)
			throw InvalidPEHeader();

		// why not /shrug
		if (nt_header.FileHeader.SizeOfOptionalHeader != sizeof(image_optional_header))
			throw InvalidPEHeader();

		// size of image
		loaded_module->m_image_size = nt_header.OptionalHeader.SizeOfImage;

		// export data directory
		const auto ex_dir = process.read<IMAGE_EXPORT_DIRECTORY>(address +
			nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		// iterate through each function in the export address table
		for (uint32_t i = 0; i < min(ex_dir.NumberOfFunctions, ex_dir.NumberOfNames); i++) {
			const auto name_addr = process.read<uint32_t>(address +
				ex_dir.AddressOfNames + (i * 4));

			// get the function name
			char name[256];
			process.read(address + name_addr, name, sizeof(name));
			name[255] = '\0';

			const auto ordinal = process.read<uint16_t>(address + ex_dir.AddressOfNameOrdinals + (i * 2));

			// write to pe_header for EAT hooking
			const auto table_addr = address + ex_dir.AddressOfFunctions + (ordinal * 4);

			// address of the function
			const auto addr = address + process.read<uint32_t>(table_addr);

			loaded_module->m_exported_funcs[name] = LoadedModule::PeEntry({ addr, table_addr });
		}

		const uint32_t iat_rva = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		uint32_t num_entries = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
		num_entries = min(num_entries - 1, num_entries);

		// iterate through each function in the import address table
		for (uint32_t i = 0; i < num_entries; i++) {
			const auto iat_entry = process.read<IMAGE_IMPORT_DESCRIPTOR>(address + iat_rva + (i * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
			if (iat_entry.Name >= loaded_module->m_image_size || iat_entry.OriginalFirstThunk >= loaded_module->m_image_size)
				break;

			// ex. KERNEL32.DLL
			char module_name[256];
			process.read(address + iat_entry.Name, module_name, 256);
			module_name[255] = '\0';

			// change to lowercase
			std::transform(std::begin(module_name), std::end(module_name), std::begin(module_name), std::tolower);

			// iterate through each thunk
			for (uint32_t j = 0; true; j += sizeof(image_thunk_data)) {
				const auto orig_thunk = process.read<image_thunk_data>(address + iat_entry.OriginalFirstThunk + j);
				if (orig_thunk.u1.AddressOfData >= loaded_module->m_image_size)
					break;

				// orig_thunk.u1.AddressOfData + 2 == IMAGE_IMPORT_BY_NAME::Name
				char func_name[256];
				process.read(address + uintptr_t(orig_thunk.u1.AddressOfData) + 2, func_name, 256);
				func_name[255] = '\0';

				const auto thunk = process.read<image_thunk_data>(address + iat_entry.FirstThunk + j);
				loaded_module->m_imported_funcs[module_name][func_name] = LoadedModule::PeEntry({
					uintptr_t(thunk.u1.Function), 
					address + iat_entry.FirstThunk + j 
				});
			}
		}
	}

	// setup (parse the pe header mostly)
	void LoadedModule::setup(const Process& process, const uintptr_t address) {
		this->m_image_base = address;
		this->m_is_valid = true;

		// reset
		m_exported_funcs.clear();
		m_imported_funcs.clear();

		// setup
		try {
			if (process.is_64bit())
				setup_internal<true>(this, process, address);
			else
				setup_internal<false>(this, process, address);
		} catch (...) {
			this->m_is_valid = false;
			throw;
		}
	}

	// get exported functions
	std::optional<LoadedModule::PeEntry> LoadedModule::get_export(const std::string func_name) const {
		if (const auto it = this->m_exported_funcs.find(func_name); it != m_exported_funcs.end())
			return it->second;

		return {};
	}

	// get imported functions
	std::optional<LoadedModule::PeEntry> LoadedModule::get_import(const std::string module_name, const std::string func_name) const {
		if (const auto it = m_imported_funcs.find(module_name); it != m_imported_funcs.end())
			if (const auto it2 = it->second.find(func_name); it2 != it->second.end())
				return it2->second;

		return {};
	}
} // namespace mango