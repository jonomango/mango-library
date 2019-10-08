#include <epic/inject.h>

#include <epic/process.h>
#include <epic/shellcode.h>


namespace mango {
	bool load_library(const Process& process, const std::string_view dll_path) {
		const auto load_library_addr = process.get_proc_addr("kernel32.dll", "LoadLibraryA");
		if (!load_library_addr)
			return false;

		// this will be where the dll path is stored in the process
		const auto str_address = uintptr_t(process.alloc_virt_mem(dll_path.size() + 1));
		if (!str_address)
			return false;

		// write the dll name
		process.write(str_address, dll_path.data(), dll_path.size() + 1);

		// this shellcode basically just calls LoadLibraryA()
		mango::Shellcode shellcode;
		if (process.is_64bit()) {
			shellcode.push(
				"\x48\x83\xEC\x20\x48\xB9",
				str_address,
				"\x48\xB8",
				load_library_addr,
				"\xFF\xD0\x48\x83\xC4\x20\xC3"
			);
		} else {
			shellcode.push(
				"\x68",
				uint32_t(str_address),
				"\xB8",
				uint32_t(load_library_addr),
				"\xFF\xD0\xC3"
			);
		}

		// execute the shellcode
		shellcode.execute(process);

		// free the memory where the dll path is stored
		process.free_virt_mem(str_address, dll_path.size() + 1);

		return true;
	}
} // namespace mango