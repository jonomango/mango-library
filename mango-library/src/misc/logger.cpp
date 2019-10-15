#include "../../include/misc/logger.h"

#include <iostream>
#include <Windows.h>


namespace mango {
	void set_attribute(const WORD attribute) {
		static const auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(handle, attribute);
	}

	std::ostream& info() {
		std::cout << "[";
		set_attribute(FOREGROUND_BLUE | FOREGROUND_GREEN);
		std::cout << "info";
		set_attribute(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
		std::cout << "] ";
		return std::cout;
	}
	std::ostream& error() {
		std::cout << "[";
		set_attribute(FOREGROUND_RED);
		std::cout << "error";
		set_attribute(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
		std::cout << "] ";
		return std::cout;
	}
} // namespace mango