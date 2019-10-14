#include <epic/process.h>
#include <epic/shellcode.h>

#include <utils/logger.h>


int main() {
	mango::Process process(GetCurrentProcessId());
	if (!process)
		return 0;

	process.manual_map("frog-x64.dll");

	system("pause");
	return 0;
}