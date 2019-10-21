#pragma once

#include <ostream>
#include <iostream>
#include <sstream>


namespace mango {
	// the data is passed in the std::stringstream
	using LoggingChannel = void(*)(std::stringstream&&);

	// logging class for debugging and stuff (can be used to output to console or a file or whatever)
	class Logger {
	public:
		// set logging channels (handlers)
		void set_info_channel(const LoggingChannel& channel) {
			this->m_info_channel = channel;
		}
		void set_success_channel(const LoggingChannel& channel) {
			this->m_success_channel = channel;
		}
		void set_error_channel(const LoggingChannel& channel) {
			this->m_error_channel = channel;
		}

		// info
		template <typename ...Args>
		void info(Args&& ...args) { this->dispatch(this->m_info_channel, std::forward<Args>(args)...); }

		// success
		template <typename ...Args>
		void success(Args&& ...args) { this->dispatch(this->m_success_channel, std::forward<Args>(args)...); }

		// error
		template <typename ...Args>
		void error(Args&& ...args) { this->dispatch(this->m_error_channel, std::forward<Args>(args)...); }

	private:
		// dispatch the contents to the appropriate channel
		template <typename ...Args>
		void dispatch(const LoggingChannel& channel, Args&& ...args) {
			if (!channel)
				return;

			// create a stringstream with the data
			std::stringstream ss;
			(ss << ... << args);
			channel(std::move(ss));
		}

	private:
		LoggingChannel m_info_channel = nullptr, 
			m_success_channel = nullptr,
			m_error_channel = nullptr;
	} inline logger;
} // namespace mango