#pragma once

#include <string_view>


namespace mango {
	class Process;

	// inject a dll into another process (using LoadLibrary)
	bool load_library(const Process& process, const std::string_view dll_path);
} // namespace mango