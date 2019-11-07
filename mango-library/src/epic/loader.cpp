#include "../../include/epic/loader.h"

#include "../../include/epic/process.h"
#include "../../include/epic/shellcode.h"
#include "../../include/misc/logger.h"
#include "../../include/misc/error_codes.h"
#include "../../include/crypto/string_encryption.h"

#include <filesystem>

#undef min


namespace mango {
	struct ManualMapData32 {
		uint32_t m_module_base;
		uint32_t m_get_proc_address;
		uint32_t m_load_library;
	};
	struct ManualMapData64 {
		uint64_t m_module_base;
		uint64_t m_get_proc_address;
		uint64_t m_load_library;
	};

	// in case i need to modify the shellcode later
#if false
	DWORD WINAPI manual_map_thread(void* arg) {
		static constexpr bool is64bit = (sizeof(void*) == 8);
		using ptr = typename std::conditional<is64bit, uint64_t, uint32_t>::type;
		using pimage_nt_headers = typename std::conditional<is64bit, PIMAGE_NT_HEADERS64, PIMAGE_NT_HEADERS32>::type;
		using image_thunk_data = typename std::conditional<is64bit, IMAGE_THUNK_DATA64, IMAGE_THUNK_DATA32>::type;
		using manual_map_data = typename std::conditional<is64bit, ManualMapData64, ManualMapData32>::type;

		const auto data = reinterpret_cast<manual_map_data*>(arg);

		const auto dos_header = PIMAGE_DOS_HEADER(data->m_module_base);
		const auto nt_header = pimage_nt_headers(data->m_module_base + dos_header->e_lfanew);

		// for fixing relocations
		const auto base_reloc_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		auto image_base_reloc = PIMAGE_BASE_RELOCATION(data->m_module_base + base_reloc_dir.VirtualAddress);
		const auto delta = ptr(data->m_module_base - nt_header->OptionalHeader.ImageBase);

		// fix up relocations
		while (image_base_reloc->VirtualAddress) {
			if (image_base_reloc->SizeOfBlock > 0) {
				const auto count = (image_base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				const auto relocations = PWORD(image_base_reloc + 1);

				// fix each relocation in the block
				for (size_t i = 0; i < count; i++) {
					if (!relocations[i])
						continue;

					const auto rva = image_base_reloc->VirtualAddress + (relocations[i] & 0xFFF);
					*reinterpret_cast<ptr*>(data->m_module_base + rva) += delta;
				}
			}

			// go to next block
			image_base_reloc = PIMAGE_BASE_RELOCATION(uintptr_t(image_base_reloc) + image_base_reloc->SizeOfBlock);
		}

		const auto iat_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

		// iterate through each function in the import address table
		for (uintptr_t i = 0; true; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
			const auto iat_entry = PIMAGE_IMPORT_DESCRIPTOR(data->m_module_base + iat_rva + i);
			if (!iat_entry->OriginalFirstThunk)
				break;

			// load the module
			const auto module_name = reinterpret_cast<const char*>(data->m_module_base + iat_entry->Name);
			const auto hmodule = ((decltype(&LoadLibraryA))data->m_load_library)(module_name);

			// iterate through each thunk
			for (uintptr_t j = 0; true; j += sizeof(image_thunk_data)) {
				const auto orig_thunk = *reinterpret_cast<ptr*>(data->m_module_base + iat_entry->OriginalFirstThunk + j);
				if (!orig_thunk || orig_thunk > nt_header->OptionalHeader.SizeOfImage)
					break;

				auto thunk = reinterpret_cast<image_thunk_data*>(data->m_module_base + iat_entry->FirstThunk + j);

				// IMAGE_IMPORT_BY_NAME::Name
				const auto func_name = reinterpret_cast<const char*>(data->m_module_base + uintptr_t(orig_thunk) + 2);
				thunk->u1.Function = ptr(((decltype(&GetProcAddress))data->m_get_proc_address)(hmodule, func_name));
			}
		}

		// call the entrypoint
		using entry_point_fn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
		const auto entry_point = entry_point_fn(data->m_module_base + nt_header->OptionalHeader.AddressOfEntryPoint);
		entry_point(HINSTANCE(data->m_module_base), DLL_PROCESS_ATTACH, nullptr);

		return 0;
	}
	void end_stub() {}
#endif

	template <bool is64bit>
	uintptr_t manual_map_internal(const Process& process, const uint8_t* const image) {
		using ptr = typename std::conditional<is64bit, uint64_t, uint32_t>::type;
		using pimage_nt_headers = typename std::conditional<is64bit, PIMAGE_NT_HEADERS64, PIMAGE_NT_HEADERS32>::type;
		using manual_map_data = typename std::conditional<is64bit, ManualMapData64, ManualMapData32>::type;

		// dos header
		const auto dos_header = PIMAGE_DOS_HEADER(image);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			throw InvalidPEHeader();

		// nt header
		const auto nt_header = pimage_nt_headers(image + dos_header->e_lfanew);
		if (nt_header->Signature != IMAGE_NT_SIGNATURE)
			throw InvalidPEHeader();

		// base address of the module in memory
		const auto module_base = process.alloc_virt_mem(nt_header->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);

		// copy the pe header to memory
		process.write(module_base, image, nt_header->OptionalHeader.SizeOfHeaders);

		// copy each section to memory
		const auto section_headers = PIMAGE_SECTION_HEADER(nt_header + 1);
		for (size_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
			process.write(module_base + section_headers[i].VirtualAddress,
				image + section_headers[i].PointerToRawData, section_headers[i].SizeOfRawData);
		}

		// shellcode for the loader thread
		Shellcode shellcode;
		if (process.is_64bit()) {
			shellcode.push(
				"\x40\x56\x57\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x4C\x8B\x09\x48\x8B\xF1\x4D\x8B\xD1\x4D\x63",
				"\x71\x3C\x4D\x03\xF1\x45\x8B\x86\xB0\x00\x00\x00\x4D\x2B\x56\x30\x4D\x03\xC1\x41\x83\x38\x00\x74",
				"\x53\x41\x8B\x40\x04\x85\xC0\x74\x3F\x4C\x8D\x48\xF8\xBA\x00\x00\x00\x00\x49\xD1\xE9\x74\x31\x66",
				"\x0F\x1F\x84\x00\x00\x00\x00\x00\x41\x0F\xB7\x44\x50\x08\x66\x85\xC0\x74\x11\x25\xFF\x0F\x00\x00",
				"\x41\x03\x00\x8B\xC8\x48\x8B\x06\x4C\x01\x14\x01\x48\xFF\xC2\x49\x3B\xD1\x72\xDC\x41\x8B\x40\x04",
				"\x4C\x03\xC0\x41\x83\x38\x00\x75\xB0\x4C\x8B\x0E\x45\x8B\xAE\x90\x00\x00\x00\x45\x33\xFF\x47\x39",
				"\x3C\x29\x4B\x8D\x3C\x29\x0F\x84\xA8\x00\x00\x00\x48\x89\x5C\x24\x50\x48\x89\x6C\x24\x58\x4C\x89",
				"\x64\x24\x60\x0F\x1F\x44\x00\x00\x8B\x4F\x0C\x48\x8B\x46\x10\x49\x03\xC9\xFF\xD0\x48\x8B\x16\x33",
				"\xED\x8B\x0F\x4C\x8B\xE0\x4C\x8B\xCA\x4C\x8B\x04\x11\x4D\x85\xC0\x74\x4F\x48\x8B\xCA\x66\x66\x66",
				"\x0F\x1F\x84\x00\x00\x00\x00\x00\x41\x8B\x46\x50\x4C\x8B\xC9\x4C\x3B\xC0\x77\x35\x8B\x5F\x10\x49",
				"\x83\xC0\x02\x48\x8B\x46\x08\x48\x03\xDA\x49\x03\xD0\x49\x8B\xCC\xFF\xD0\x48\x89\x04\x2B\x48\x83",
				"\xC5\x08\x48\x8B\x16\x8B\x07\x48\x8B\xCA\x48\x03\xC2\x4C\x8B\xCA\x4C\x8B\x04\x28\x4D\x85\xC0\x75",
				"\xBF\x49\x83\xC7\x14\x4B\x8D\x3C\x29\x49\x03\xFF\x83\x3F\x00\x0F\x85\x7B\xFF\xFF\xFF\x4C\x8B\x64",
				"\x24\x60\x48\x8B\x6C\x24\x58\x48\x8B\x5C\x24\x50\x41\x8B\x46\x28\x45\x33\xC0\x49\x03\xC1\x49\x8B",
				"\xC9\x41\x8D\x50\x01\xFF\xD0\x33\xC0\x48\x83\xC4\x20\x41\x5F\x41\x5E\x41\x5D\x5F\x5E\xC3\xCC\xCC",
				"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x83\x49\x18\x04\x48\x8B\xC1\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
				"\x48\x83\x79\x30\x10\x48\x8D\x41\x18\x72\x03\x48\x8B\x00\xC3\xCC\x48\x89\x5C\x24\x08\x48\x89\x74",
				"\x24\x10\x57\x48\x83\xEC\x20\x49\x8B\xD9\x49\x8B\xF0\x48\x8B\xFA\x4D\x85\xC9\x74\x41\x48\x85\xC9",
				"\x75\x27\xFF\x15\x08\x80\x00\x00\xC7\x00\x16\x00\x00\x00\xFF\x15\xE4\x7F\x00\x00\xB8\x16\x00\x00",
				"\x00\x48\x8B\x5C\x24\x30\x48\x8B\x74\x24\x38\x48\x83\xC4\x20\x5F\xC3\x48\x85\xF6\x74\x22\x48\x3B"
			);
		} else {
			shellcode.push(
				"\x55\x8B\xEC\x83\xEC\x14\x8B\x4D\x08\x53\x56\x57\x8B\x11\x8B\xDA\x8B\x42\x3C\x03\xC2\x89\x45\xF8",
				"\x8B\xB0\xA0\x00\x00\x00\x2B\x58\x34\x03\xF2\x83\x3E\x00\x74\x45\x8B\x46\x04\x85\xC0\x74\x32\x8D",
				"\x78\xF8\xBA\x00\x00\x00\x00\xD1\xEF\x74\x26\x0F\x1F\x44\x00\x00\x0F\xB7\x44\x56\x08\x66\x85\xC0",
				"\x74\x0F\x8B\x09\x25\xFF\x0F\x00\x00\x03\x06\x01\x1C\x01\x8B\x4D\x08\x42\x3B\xD7\x72\xE2\x8B\x46",
				"\x04\x03\xF0\x83\x3E\x00\x75\xC0\x8B\x11\x8B\x45\xF8\x8B\x88\x80\x00\x00\x00\x83\x3C\x0A\x00\x8D",
				"\x1C\x0A\x89\x4D\xEC\xC7\x45\xF4\x00\x00\x00\x00\x0F\x84\x83\x00\x00\x00\x8B\x75\x08\x0F\x1F\x00",
				"\x8B\x4B\x0C\x8B\x46\x08\x03\xCA\x51\xFF\xD0\x8B\x3E\x8B\xD7\x8B\x0B\x89\x45\xF0\xC7\x45\xFC\x00",
				"\x00\x00\x00\x8B\x04\x0F\x85\xC0\x74\x44\x8B\xCF\x8B\xD1\x8B\x4D\xF8\x3B\x41\x50\x77\x38\x8B\x73",
				"\x10\x8B\x4D\x08\x03\xF7\x03\x75\xFC\x83\xC7\x02\x03\xC7\x50\xFF\x75\xF0\x8B\x49\x04\xFF\xD1\x8B",
				"\x4D\xFC\x89\x06\x83\xC1\x04\x8B\x75\x08\x8B\x03\x89\x4D\xFC\x8B\x3E\x03\xC7\x8B\xD7\x8B\x04\x08",
				"\x8B\xCF\x85\xC0\x75\xBE\x8B\x45\xF4\x83\xC0\x14\x89\x45\xF4\x8D\x1C\x02\x03\x5D\xEC\x83\x3B\x00",
				"\x75\x86\x8B\x45\xF8\x8B\x40\x28\x6A\x00\x6A\x01\x52\x03\xC2\xFF\xD0\x5F\x5E\x33\xC0\x5B\x8B\xE5",
				"\x5D\xC2\x04\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x55\x8B\xEC\x8B\x45\x08\x83\x48",
				"\x14\x04\x5D\xC3\xCC\xCC\xCC\xCC\x83\x79\x20\x10\x8D\x41\x0C\x72\x02\x8B\x00\xC3\xCC\xCC\xCC\xCC",
				"\x55\x8B\xEC\x6A\xFF\x68\x70\xB9\x83\x00\x64\xA1\x00\x00\x00\x00"
			);
		}

		// data to pass to the loader thread
		manual_map_data mm_data;
		mm_data.m_module_base = ptr(module_base);
		mm_data.m_get_proc_address = ptr(process.get_proc_addr(enc_str("kernel32.dll"), enc_str("GetProcAddress")));
		mm_data.m_load_library = ptr(process.get_proc_addr(enc_str("kernel32.dll"), enc_str("LoadLibraryA")));

		// allocate and copy the loader data to the process's memory space
		const auto thread_argument = process.alloc_virt_mem(sizeof(mm_data));
		process.write(thread_argument, mm_data);

		shellcode.execute(process, thread_argument);
		
		return module_base;
	}

	// inject a dll into another process (using LoadLibrary)
	uintptr_t load_library(const Process& process, const std::string& dll_path) {
		const auto func_addr = process.get_proc_addr(enc_str("kernel32.dll"), enc_str("LoadLibraryA"));
		if (!func_addr)
			throw FailedToGetFunctionAddress();

		// this will be where the dll path is stored in the process
		const auto str_address = uintptr_t(process.alloc_virt_mem(dll_path.size() + 1));

		// for the return value of LoadLibraryA
		const auto ret_address = uintptr_t(process.alloc_virt_mem(process.get_ptr_size()));

		// write the dll name
		process.write(str_address, dll_path.data(), dll_path.size() + 1);

		// HMODULE
		uintptr_t ret_value = 0;

		// this shellcode basically just calls LoadLibraryA()
		if (process.is_64bit()) {
			mango::Shellcode(
				"\x48\x83\xEC\x20", // sub rsp, 0x20
				"\x48\xB9", str_address, // movabs rcx, str_address
				"\x48\xB8", func_addr, // movabs rax, func_addr
				"\xFF\xD0", // call rax
				"\x48\xA3", ret_address, // movabs [ret_address], rax
				"\x48\x83\xC4\x20", // add rsp, 0x20
				"\x31\xC0", // xor eax, eax
				Shellcode::ret()
			).execute(process);

			// the HMODULE returned by LoadLibrary
			ret_value = uintptr_t(process.read<uint64_t>(ret_address));
		} else {
			mango::Shellcode(
				"\x68", uint32_t(str_address), // push str_address
				"\xB8", uint32_t(func_addr), // mov eax, func_addr
				"\xFF\xD0", // call eax
				"\xA3", uint32_t(ret_address), // mov [ret_address], eax
				Shellcode::ret()
			).execute(process);

			// the HMODULE returned by LoadLibrary
			ret_value = process.read<uint32_t>(ret_address);
		}

		// free memory
		process.free_virt_mem(str_address);
		process.free_virt_mem(ret_address);

		// truncated if called from a 64bit program to a 32bit program
		return ret_value;
	}

	// manual map a dll into another process
	uintptr_t manual_map(const Process& process, const std::string& dll_path) {
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
		const auto image_buffer = new uint8_t[file_size];
		if (!image_buffer)
			throw FailedToAllocateVirtualMemory();

		// read file
		if (DWORD num_bytes = 0; !ReadFile(file_handle, image_buffer, file_size, &num_bytes, FALSE))
			throw FailedToReadFile();

		// don't need it anymore
		CloseHandle(file_handle);

		const auto ret_value = manual_map(process, image_buffer);

		// free memory
		delete[] image_buffer;

		return ret_value;
	}
	uintptr_t manual_map(const Process& process, const uint8_t* const image) {
		return process.is_64bit() ?
			manual_map_internal<true>(process, image) :
			manual_map_internal<false>(process, image);
	}
} // namespace mango