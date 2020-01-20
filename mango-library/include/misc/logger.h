#pragma once

#include <ostream>
#include <sstream>
#include <array>


namespace mango {
	enum class LogType {
		info,
		success,
		warning,
		error
	};

	// the data is passed in the std::stringstream
	using LoggingChannel = void(*)(std::ostringstream&&);

#pragma warning(push)
#pragma warning(disable : 4201) // warning C4201: nonstandard extension used: nameless struct/union
	union LoggingChannels {
		LoggingChannel channels[1];
		struct {
			LoggingChannel info,
				success,
				warning,
				error;
		};
	};
#pragma warning(pop)

	// basic colored console logging
	LoggingChannels basic_colored_logging();

	// for printing to an ostream
	// NOTE: using these logging channels when the stream object's lifetime
	//       is over will crash the program, make sure to set new logging channels
	//       once the stream dies
	LoggingChannels basic_ostream_logging(std::ostream& stream);

	// logging class for debugging and stuff (can be used to output to console or a file or whatever)
	// NOTE: this is implementated through stringstreams so this is NOT optimized
	// TODO: add support for multiple concurrent logging channels
	class Logger {
	public:
		// set logging channels (handlers)
		// pass nullptr to ignore logs for that specific channel
		void set_channel(const LogType type, const LoggingChannel channel) noexcept {
			this->m_channels.channels[size_t(type)] = channel;
		}

		// set all logging channels at once
		void set_channels(const LoggingChannels& channels) noexcept {
			this->m_channels = channels;
		}

		// info
		template <typename ...Args>
		void info(Args&& ...args) { this->dispatch(LogType::info, std::forward<Args>(args)...); }

		// success
		template <typename ...Args>
		void success(Args&& ...args) { this->dispatch(LogType::success, std::forward<Args>(args)...); }

		// warning
		template <typename ...Args>
		void warning(Args&& ...args) { this->dispatch(LogType::warning, std::forward<Args>(args)...); }

		// error
		template <typename ...Args>
		void error(Args&& ...args) { this->dispatch(LogType::error, std::forward<Args>(args)...); }

		// dispatch the contents to the appropriate channel
		template <typename ...Args>
		void dispatch(const LogType type, Args&& ...args) {
			const auto channel(this->m_channels.channels[size_t(type)]);
			if (!channel)
				return;

			// create a stringstream with the data
			std::ostringstream ss{};
			(ss << ... << args);
			channel(std::move(ss));
		}
	private:
		LoggingChannels m_channels{};
	} inline logger;
} // namespace mango