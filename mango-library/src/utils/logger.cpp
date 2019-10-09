#include <utils/logger.h>

#include <iostream>
#include <Windows.h>


namespace mango {
	void set_attribute(const WORD attribute) {
		static const auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(handle, attribute);
	}

	std::wostream& info() {
		std::wcout << "[";
		set_attribute(FOREGROUND_BLUE | FOREGROUND_GREEN);
		std::wcout << "info";
		set_attribute(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
		std::wcout << "] ";
		return std::wcout;
	}
	std::wostream& error() {
		std::wcout << "[";
		set_attribute(FOREGROUND_RED);
		std::wcout << "error";
		set_attribute(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
		std::wcout << "] ";
		return std::wcout;
	}
} // namespace mango