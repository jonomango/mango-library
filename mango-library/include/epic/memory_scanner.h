#pragma once

#include "../misc/misc.h"
#include "../epic/process.h"

#include <string_view>
#include <ostream>
#include <vector>


namespace mango::memscn {
	struct Range {
		uintptr_t start = 0;
		size_t size = size_t(-1);
	};

	static constexpr auto range_all = Range{ .start = 0, .size = size_t(-1) };

	// readable data isn't an option since it has to be allowed (duh)
	struct Filter {
		bool executable;
		bool writeable;
	};

	static constexpr auto all_filter = Filter{ .executable = true, .writeable = true };
	static constexpr auto code_filter = Filter{ .executable = true, .writeable = false };
	static constexpr auto data_filter = Filter{ .executable = false, .writeable = true };

	class Pattern {
	public:
		// ida-style pattern
		// eg: "AA ? BB CC ? ? DD"
		//     "aa ? bb cc ? ? dd"
		//     "aa?bbcc??dd"
		Pattern(const std::string_view pattern);

		// code-style pattern
		// eg: "\xAA\x00\xBB\xCC\x00\x00\xDD" and "X?XX??X"
		//     "\xaa\x00\xbb\xcc\x00\x00\xdd" and "x?xx??x"
		Pattern(const void* const pattern, const std::string_view mask);

		// same as code-style pattern except the mask has no wildcards
		Pattern(const void* const pattern, const size_t size);

		// does pattern match?
		bool matches(const uint8_t* buffer) const;

		// number of bytes
		size_t size() const noexcept { return this->m_data.size(); }

	private:
		std::vector<uint16_t> m_data;

		friend std::ostream& operator<<(std::ostream&, const Pattern&);
		friend std::wostream& operator<<(std::wostream&, const Pattern&);
	};

	// search the memory for the provided pattern
	std::vector<uintptr_t> scan(const Process& process, const Pattern& pattern, 
		const Range& range = range_all, const Filter& filter = all_filter);
	std::vector<uintptr_t> scan(const Process& process, const Pattern& pattern,
		const std::string_view modulename, const Filter& filter = all_filter);

	// overload << operator
	std::ostream& operator<<(std::ostream& stream, const Pattern& pattern);
	std::wostream& operator<<(std::wostream& stream, const Pattern& pattern);
} // namespace mango::memscn