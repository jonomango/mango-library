#include <epic/process.h>
#include <epic/vmt_hook.h>

#include <utils/logger.h>

#include <iostream>


int main() {
	mango::Process process(GetCurrentProcessId());
	if (!process)
		return 0;

	mango::info() << process.get_name() << std::endl;

	system("pause");
	return 0;
}