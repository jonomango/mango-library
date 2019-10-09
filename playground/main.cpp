#include <iostream>

#include <epic/process.h>
#include <epic/pe_header.h>
#include <epic/shellcode.h>
#include <epic/inject.h>
#include <epic/vmt_hook.h>
#include <utils/logger.h>
#include <utils/vector.h>
#include <utils/color.h>


int main() {
	mango::Process process;
	if (!process) {
		return 0;
	}

	mango::Vector<float, 3> vec(2.f);
	std::cout << vec << std::endl;

	mango::ColorRGBA<uint8_t> rgba;
	std::cout << rgba << std::endl;

	mango::ColorHSBA<float> hsba(0.f, 1.f, 0.f);
	std::cout << hsba << std::endl;

	system("pause");
	return 0;
}