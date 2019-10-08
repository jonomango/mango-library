#include <utils/logger.h>

#include <iostream>
#include <Windows.h>


namespace mango {
	std::ostream& log() {
		std::cout << "[info] ";

		return std::cout;
	}

	std::wostream& wlog() {
		std::wcout << L"[info] ";

		return std::wcout;
	}
} // namespace mango