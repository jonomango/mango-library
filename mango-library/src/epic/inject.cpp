#include "../../include/epic/process.h"

#include "../../include/epic/shellcode.h"
#include "../../include/misc/logger.h"
#include "../../include/misc/error_codes.h"

#undef min


namespace mango {
	template <bool is64bit>
	uintptr_t manual_map_internal(const Process& process, const uint8_t* const image) {
		using ptr = typename std::conditional<is64bit, uint64_t, uint32_t>::type;
		using pimage_nt_headers = typename std::conditional<is64bit, PIMAGE_NT_HEADERS64, PIMAGE_NT_HEADERS32>::type;
		using image_thunk_data = typename std::conditional<is64bit, IMAGE_THUNK_DATA64, IMAGE_THUNK_DATA32>::type;

		// dos header
		const auto dos_header = PIMAGE_DOS_HEADER(image);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			throw InvalidPEHeader();

		// nt header
		const auto nt_header = pimage_nt_headers(image + dos_header->e_lfanew);
		if (nt_header->Signature != IMAGE_NT_SIGNATURE)
			throw InvalidPEHeader();

		// base address of the module in memory
		const auto module_base = uintptr_t(process.alloc_virt_mem(nt_header->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE));

		// copy the pe header to memory
		process.write(module_base, image, nt_header->OptionalHeader.SizeOfHeaders);

		// write each section to memory
		const auto section_headers = PIMAGE_SECTION_HEADER(nt_header + 1);
		for (size_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
			process.write(module_base + section_headers[i].VirtualAddress,
				image + section_headers[i].PointerToRawData, section_headers[i].SizeOfRawData);
		}

		// difference between where the pe expected to be loaded at and where it actually will be loaded at
		const auto delta = ptr(module_base - nt_header->OptionalHeader.ImageBase);

		// fix relocations
		auto curr_reloc_addr = module_base + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		while (true) {
			const auto relocation = process.read<IMAGE_BASE_RELOCATION>(curr_reloc_addr);
			if (!relocation.VirtualAddress)
				break;

			const auto num = (relocation.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			const auto reloc_info_addr = curr_reloc_addr + sizeof(relocation);
			for (size_t i = 0; i < num; ++i) {
				const auto reloc_info = process.read<WORD>(reloc_info_addr + i * sizeof(WORD));
				const auto address = module_base + (relocation.VirtualAddress + (reloc_info & 0xFFF));
				const auto value = process.read<ptr>(address);
				process.write<ptr>(address, value + delta);
			}

			curr_reloc_addr += relocation.SizeOfBlock;
		}

		const auto iat_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		size_t num_entries = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
		num_entries = std::min(num_entries - 1, num_entries);

		// iterate through each function in the import address table
		for (size_t i = 0; i < num_entries; i++) {
			const auto iat_entry = process.read<IMAGE_IMPORT_DESCRIPTOR>(module_base + iat_rva + (i * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
			if (iat_entry.Name >= nt_header->OptionalHeader.SizeOfImage || iat_entry.OriginalFirstThunk >= nt_header->OptionalHeader.SizeOfImage)
				break;

			// ex. KERNEL32.DLL
			char module_name[256];
			process.read(module_base + iat_entry.Name, module_name, 256);
			module_name[255] = '\0';

			auto module_addr = process.get_module_addr(module_name);
			if (!module_addr)
				module_addr = process.load_library(module_name);

			// iterate through each thunk
			for (uintptr_t j = 0; true; j += sizeof(image_thunk_data)) {
				const auto orig_thunk = process.read<image_thunk_data>(module_base + iat_entry.OriginalFirstThunk + j);
				if (orig_thunk.u1.AddressOfData >= nt_header->OptionalHeader.SizeOfImage)
					break;
			
				// orig_thunk.u1.AddressOfData + 2 == IMAGE_IMPORT_BY_NAME::Name
				char func_name[256];
				process.read(module_base + uintptr_t(orig_thunk.u1.AddressOfData) + 2, func_name, 256);
				func_name[255] = '\0';
			
				auto thunk = process.read<image_thunk_data>(module_base + iat_entry.FirstThunk + j);
				thunk.u1.Function = ptr(process.get_proc_addr(module_addr, func_name));
				process.write<image_thunk_data>(module_base + iat_entry.FirstThunk + j, thunk);
			}
		}

		// call the entry point
		if (nt_header->OptionalHeader.AddressOfEntryPoint) {
			const auto entry_point = module_base + nt_header->OptionalHeader.AddressOfEntryPoint;

			if constexpr (is64bit) {
				Shellcode(
					"\x48\x83\xEC\x20", // sub rsp, 0x20
					"\x49\xB8", uint64_t(0), // movabs r8, 0
					"\xBA", uint32_t(DLL_PROCESS_ATTACH), // mov edx, DLL_PROCESS_ATTACH
					"\x48\xB9", uint64_t(module_base), // movabs rcx, module_base
					"\x48\xB8", uint64_t(entry_point), // movabs rax, entry_point
					"\xFF\xD0", // call rax
					"\x48\x83\xC4\x20", // add rsp, 0x20
					"\xC3" // ret
				).execute(process);
			} else {
				Shellcode(
					"\x68", uint32_t(0), // push 0
					"\x68", uint32_t(DLL_PROCESS_ATTACH), // push DLL_PROCESS_ATTACH
					"\x68", uint32_t(module_base), // push module_base
					"\xB8", uint32_t(entry_point), // mov eax, entry_point
					"\xFF\xD0", // call eax
					"\xC3" // ret
				).execute(process);
			}
		}

		return uintptr_t(module_base);
	}

	uintptr_t Process::load_library(const std::string& dll_path) const {
		const auto func_addr = this->get_proc_addr("kernel32.dll", "LoadLibraryA");
		if (!func_addr)
			throw FailedToGetFunctionAddress();

		// this will be where the dll path is stored in the process
		const auto str_address = uintptr_t(this->alloc_virt_mem(dll_path.size() + 1));

		// for the return value of LoadLibraryA
		const auto ret_address = uintptr_t(this->alloc_virt_mem(this->get_ptr_size()));

		// write the dll name
		this->write(str_address, dll_path.data(), dll_path.size() + 1);

		// HMODULE
		uintptr_t ret_value = 0;

		// this shellcode basically just calls LoadLibraryA()
		if (this->is_64bit()) {
			mango::Shellcode(
				"\x48\x83\xEC\x20", // sub rsp, 0x20
				"\x48\xB9", str_address, // movabs rcx, str_address
				"\x48\xB8", func_addr, // movabs rax, func_addr
				"\xFF\xD0", // call rax
				"\x48\xA3", ret_address, // movabs [ret_address], rax
				"\x48\x83\xC4\x20", // add rsp, 0x20
				"\xC3" // ret
			).execute(*this);

			// the HMODULE returned by LoadLibrary
			ret_value = uintptr_t(this->read<uint64_t>(ret_address));
		} else {
			mango::Shellcode(
				"\x68", uint32_t(str_address), // push str_address
				"\xB8", uint32_t(func_addr), // mov eax, func_addr
				"\xFF\xD0", // call eax
				"\xA3", uint32_t(ret_address), // mov [ret_address], eax
				"\xC3" // ret
			).execute(*this);

			// the HMODULE returned by LoadLibrary
			ret_value = this->read<uint32_t>(ret_address);
		}
		
		// free memory
		this->free_virt_mem(str_address);
		this->free_virt_mem(ret_address);

		// truncated if called from a 64bit program to a 32bit program
		return ret_value;
	}

	uintptr_t Process::manual_map(const std::string& dll_path) const {
		// open file
		const auto file_handle = CreateFileA(
			dll_path.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);

		// invalid handle
		if (file_handle == INVALID_HANDLE_VALUE)
			throw InvalidFileHandle();

		// file size
		const auto file_size = GetFileSize(file_handle, NULL);
		if (file_size == INVALID_FILE_SIZE)
			throw InvalidFileSize();

		// allocate a buffer for the file contents
		const auto image_buffer = static_cast<uint8_t*>(VirtualAlloc(nullptr, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!image_buffer)
			throw FailedToAllocateVirtualMemory();

		// read file
		if (DWORD num_bytes = 0; !ReadFile(file_handle, image_buffer, file_size, &num_bytes, FALSE))
			throw FailedToReadFile();

		// don't need it anymore
		CloseHandle(file_handle);

		const auto ret_value = this->manual_map(image_buffer);

		// free memory
		VirtualFree(image_buffer, 0, MEM_RELEASE);

		return ret_value;
	}
	uintptr_t Process::manual_map(const uint8_t* const image) const {
		return this->is_64bit() ? 
			manual_map_internal<true>(*this, image) :
			manual_map_internal<false>(*this, image);
	}
} // namespace mango