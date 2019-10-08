#include <iostream>

#include <epic/process.h>
#include <epic/pe_header.h>
#include <epic/shellcode.h>
#include <epic/inject.h>


int main() {
	mango::Process process;
	if (!process) {
		return 0;
	}

	mango::load_library(process, "frog.dll");

	system("pause");
	return 0;
}