#include <iostream>

#include <epic/process.h>
#include <epic/pe_header.h>
#include <epic/shellcode.h>
#include <epic/inject.h>
#include <epic/vmt_hook.h>
#include <epic/iat_hook.h>

#include <utils/logger.h>
#include <utils/vector.h>
#include <utils/color.h>


int main() {
	mango::Process process;
	if (!process) {
		system("pause");
		return 0;
	}

	system("pause");
	return 0;
}