#include <iostream>

#include <epic/process.h>
#include <epic/pe_header.h>
#include <epic/shellcode.h>
#include <epic/inject.h>
#include <epic/vmt_hook.h>
#include <utils/logger.h>
#include <utils/vector.h>


int main() {
	mango::Process process;
	if (!process) {
		return 0;
	}

	mango::Vector<float, 3> vec(2.f, 1.f, 0.f);
	std::cout << vec.length() << std::endl;
	vec.normalize();
	std::cout << vec << std::endl;
	std::cout << vec.length() << std::endl;

	system("pause");
	return 0;
}