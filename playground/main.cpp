#include <iostream>

#include "tests.h"

#include <epic/process.h>
#include <misc/logger.h>
#include <misc/windows_defs.h>
#include <crypto/encrypted_string.h>
#include <crypto/fnv_hash.h>


int main() {
	encrypt_string("Hello world!");

	getchar();
	return 0;
}