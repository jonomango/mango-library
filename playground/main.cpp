#include <iostream>

#include <epic/process.h>
#include <epic/pe_header.h>


int main() {
	mango::Process process;
	if (!process) {
		return 0;
	}

	if (mango::PeHeader pe_header(process, process.get_module("")->m_address); pe_header) {



		std::cout << "[imports]" << std::endl;
		for (const auto& [mod_name, x] : pe_header.get_imports()) {
			std::cout << "[*] " << mod_name << std::endl;
			for (const auto& [func_name, entry] : x) {
				std::cout << func_name << " " << std::hex << entry.m_address << std::endl;
			}
		}
	}
	
	system("pause");
	return 0;
}