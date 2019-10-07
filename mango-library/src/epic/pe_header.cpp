#include <epic/pe_header.h>

#include <epic/process.h>
#include <iostream>
#include <algorithm>


namespace mango {
	PeHeader::PeHeader(const Process& process, const void* const address) 
		: PeHeader(process, uintptr_t(address)) {}
	PeHeader::PeHeader(const Process& process, const uintptr_t address) {
		this->m_image_base = address;
		this->m_is_valid = process.is_64bit() ? 
			this->setup64(process, address) :
			this->setup32(process, address);
	}

	bool PeHeader::setup32(const Process& process, const uintptr_t address) {
		const auto dos_header = process.read<IMAGE_DOS_HEADER>(address);
		const auto nt_header = process.read<IMAGE_NT_HEADERS32>(address + dos_header.e_lfanew);

		// not a PE signature
		if (nt_header.Signature != IMAGE_NT_SIGNATURE)
			return false;

		// why not /shrug
		if (nt_header.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER32))
			return false;

		// size of image
		this->m_image_size = nt_header.OptionalHeader.SizeOfImage;

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

			// write to this for EAT hooking
			const auto table_addr = address + ex_dir.AddressOfFunctions + (ordinal * 4);

			// address of the function
			const auto addr = address + process.read<uint32_t>(table_addr);

			m_exported_funcs[name] = PeEntry({ addr, table_addr });
		}

		const uint32_t iat_rva = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		uint32_t num_entries = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
		num_entries = std::clamp(num_entries - 1, 0U, num_entries);

		// iterate through each function in the import address table
		for (uint32_t i = 0; i < num_entries; i++) {
			const auto iat_entry = process.read<IMAGE_IMPORT_DESCRIPTOR>(address + iat_rva + (i * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
			if (iat_entry.Name >= m_image_size || iat_entry.OriginalFirstThunk >= m_image_size)
				break;

			// ex. KERNEL32.DLL
			char module_name[256];
			process.read(address + iat_entry.Name, module_name, 256);
			module_name[255] = '\0';

			// iterate through each thunk
			for (uint32_t j = 0; true; j += sizeof(IMAGE_THUNK_DATA32)) {
				const auto orig_thunk = process.read<IMAGE_THUNK_DATA32>(address + iat_entry.OriginalFirstThunk + j);
				if (orig_thunk.u1.AddressOfData >= m_image_size)
					break;

				// orig_thunk.u1.AddressOfData + 2 == IMAGE_IMPORT_BY_NAME::Name
				char func_name[256];
				process.read(address + uintptr_t(orig_thunk.u1.AddressOfData) + 2, func_name, 256);
				func_name[255] = '\0';

				const auto thunk = process.read<IMAGE_THUNK_DATA32>(address + iat_entry.FirstThunk + j);
				m_imported_funcs[module_name][func_name] = PeEntry({ uintptr_t(thunk.u1.Function), address + iat_entry.FirstThunk + j });
			}
		}

		return true;
	}
	bool PeHeader::setup64(const Process& process, const uintptr_t address) {
		const auto dos_header = process.read<IMAGE_DOS_HEADER>(address);
		const auto nt_header = process.read<IMAGE_NT_HEADERS64>(address + dos_header.e_lfanew);

		// not a PE signature
		if (nt_header.Signature != IMAGE_NT_SIGNATURE)
			return false;

		// why not /shrug
		if (nt_header.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64))
			return false;

		// size of image
		this->m_image_size = nt_header.OptionalHeader.SizeOfImage;

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

			// write to this for EAT hooking
			const auto table_addr = address + ex_dir.AddressOfFunctions + (ordinal * 4);

			// address of the function
			const auto addr = address + process.read<uint32_t>(table_addr);

			m_exported_funcs[name] = PeEntry({ addr, table_addr });
		}

		const uint32_t iat_rva = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		uint32_t num_entries = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
		num_entries = std::clamp(num_entries - 1, 0U, num_entries);

		// iterate through each function in the import address table
		for (uint32_t i = 0; i < num_entries; i++) {
			const auto iat_entry = process.read<IMAGE_IMPORT_DESCRIPTOR>(address + iat_rva + (i * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
			if (iat_entry.Name >= m_image_size || iat_entry.OriginalFirstThunk >= m_image_size)
				break;

			// ex. KERNEL32.DLL
			char module_name[256];
			process.read(address + iat_entry.Name, module_name, 256);
			module_name[255] = '\0';

			// iterate through each thunk
			for (uint32_t j = 0; true; j += sizeof(IMAGE_THUNK_DATA64)) {
				const auto orig_thunk = process.read<IMAGE_THUNK_DATA64>(address + iat_entry.OriginalFirstThunk + j);
				if (orig_thunk.u1.AddressOfData >= m_image_size)
					break;

				// orig_thunk.u1.AddressOfData + 2 == IMAGE_IMPORT_BY_NAME::Name
				char func_name[256];
				process.read(address + uintptr_t(orig_thunk.u1.AddressOfData) + 2, func_name, 256);
				func_name[255] = '\0';

				const auto thunk = process.read<IMAGE_THUNK_DATA64>(address + iat_entry.FirstThunk + j);
				m_imported_funcs[module_name][func_name] = PeEntry({ uintptr_t(thunk.u1.Function), address + iat_entry.FirstThunk + j });
			}
		}

		return true;
	}

	std::optional<PeHeader::PeEntry> PeHeader::get_export(const std::string func_name) const {
		if (const auto it = this->m_exported_funcs.find(func_name); it != m_exported_funcs.end())
			return it->second;

		return {};
	}
	std::optional<PeHeader::PeEntry> PeHeader::get_import(const std::string module_name, const std::string func_name) const {
		if (const auto it = m_imported_funcs.find(module_name); it != m_imported_funcs.end()) {
			if (const auto it2 = it->second.find(func_name); it2 != it->second.end())
				return it2->second;

			return {};
		}

		return {};
	}
} // namespace mango