#include "../../include/misc/logger.h"

#include "../../include/misc/error_codes.h"

#include <iostream>
#include <Windows.h>


namespace mango {
	namespace impl {
		void console_print_colored(const HANDLE console_handle, const uint16_t attribute,
			const std::string_view prefix, const std::string_view text) 
		{
			// the prefix is colored, the text is white
			static constexpr auto white = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;

			SetConsoleTextAttribute(console_handle, white);
			std::cout << '[';

			// print the prefix
			SetConsoleTextAttribute(console_handle, attribute);
			std::cout << prefix;

			// print the text
			SetConsoleTextAttribute(console_handle, white);
			std::cout << "] " << text << std::endl;
		}
	} // namespace impl

	// basic colored console logging
	LoggingChannels basic_colored_logging() {
		// has to be static
		static const auto console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (console_handle == INVALID_HANDLE_VALUE)
			throw InvalidConsoleHandle{};

		return LoggingChannels{
			// info channel
			.info = [](std::ostringstream&& ss) {
				impl::console_print_colored(console_handle, FOREGROUND_BLUE | FOREGROUND_GREEN, "info", ss.str());
			},
			// success channel
			.success = [](std::ostringstream&& ss) {
				impl::console_print_colored(console_handle, FOREGROUND_GREEN, "success", ss.str());
			},
			// warning channel
			.warning = [](std::ostringstream&& ss) {
				impl::console_print_colored(console_handle, FOREGROUND_RED | FOREGROUND_GREEN, "warning", ss.str());
			},
			// error channel
			.error = [](std::ostringstream&& ss) {
				impl::console_print_colored(console_handle, FOREGROUND_RED, "error", ss.str());
			}
		};
	}

	// for printing to an ostream
	// NOTE: using these logging channels when the stream object's lifetime
	//       is over will crash the program, make sure to set new logging channels
	//       once the stream dies
	LoggingChannels basic_ostream_logging(std::ostream& stream) {
		// yes, this is needed to "bind" the stram object
		static const auto console_print = [&](const std::string_view prefix, const std::string_view text) {
			stream << '[' << prefix << "] " << text << std::endl;
		};

		return LoggingChannels{
			// info channel
			.info = [](std::ostringstream&& ss) {
				console_print("info", ss.str());
			},
			// success channel
			.success = [](std::ostringstream&& ss) {
				console_print("success", ss.str());
			},
			// warning channel
			.warning = [](std::ostringstream&& ss) {
				console_print("warning", ss.str());
			},
			// error channel
			.error = [](std::ostringstream&& ss) {
				console_print("error", ss.str());
			}
		};
	}
} // namespace mango