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

	// return false to discard memory region based on protection
	using Filter = bool(*)(uint32_t protection);

	// some default filters
	constexpr bool all_filter(uint32_t) {
		return true;
	}
	constexpr bool code_filter(const uint32_t protection) {
		return protection & PAGE_EXECUTE || protection & PAGE_EXECUTE_READ ||
			protection & PAGE_EXECUTE_READWRITE || protection & PAGE_EXECUTE_WRITECOPY;
	}
	constexpr bool data_filter(const uint32_t protection) {
		return !code_filter(protection);
	}

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
	std::vector<uintptr_t> find(const Process& process, const Pattern& pattern,
		const Range& range = range_all, const Filter& filter = all_filter);
	std::vector<uintptr_t> find(const Process& process, const Pattern& pattern,
		const std::string_view modulename, const Filter& filter = all_filter);

	// return the first occurance or 0
	inline uintptr_t find_first(const Process& process, const Pattern& pattern,
		const Range& range = range_all, const Filter& filter = all_filter) 
	{
		auto const matching_addresses = find(process, pattern, range, filter);
		if (matching_addresses.empty())
			return 0;
		return matching_addresses.front();
	}
	inline uintptr_t find_first(const Process& process, const Pattern& pattern,
		const std::string_view modulename, const Filter& filter = all_filter) 
	{
		auto const matching_addresses = find(process, pattern, modulename, filter);
		if (matching_addresses.empty())
			return 0;
		return matching_addresses.front();
	}

	// overload << operator
	std::ostream& operator<<(std::ostream& stream, const Pattern& pattern);
	std::wostream& operator<<(std::wostream& stream, const Pattern& pattern);
} // namespace mango::memscn