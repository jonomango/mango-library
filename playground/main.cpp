#include <iostream>

#include "tests.h"

#include <epic/process.h>

#include <misc/windows_defs.h>
#include <misc/logger.h>
#include <crypto/encrypted_string.h>

#include <Windows.h>
#include <winternl.h>


int main() {
	std::cout << encrypt_str("Hello world!") << std::endl;

	getchar();
	return 0;
}