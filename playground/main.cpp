#include <iostream>

#include <epic/process.h>
#include <epic/pe_header.h>


int main() {
	mango::Process process;
	if (!process) {
		return 0;
	}

	std::cout << std::hex << process.get_proc_addr("kernel32.dll", "CreateFileA") << std::endl;
	std::cout << std::hex << GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "CreateFileA") << std::endl;
	
	system("pause");
	return 0;
}