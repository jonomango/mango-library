#include <iostream>

#include "tests.h"

#include <epic/process.h>

#include <misc/windows_defs.h>
#include <misc/logger.h>

#include <Windows.h>
#include <winternl.h>


int main() {
	run_unit_tests();

	getchar();
	return 0;
}