#include <iostream>

#include <epic/process.h>


int main() {
	mango::Process process;
	if (!process) {
		return 0;
	}

	std::cout << "name: " << process.get_name() << std::endl;
	std::cout << "architecture: " << (process.is_64bit() ? "x64" : "x86") << std::endl;
	
	system("pause");
	return 0;
}