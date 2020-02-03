#define NOMINMAX
#include "../../include/epic/memory_scanner.h"

#include "../../include/misc/error_codes.h"

#include <cctype>
#include <iomanip>


namespace {
	uint8_t parse_byte(uint8_t left, uint8_t right) {
		// case insensitive
		left = uint8_t(std::toupper(left));
		right = uint8_t(std::toupper(right));

		uint8_t value(0);
		if (left >= '0' && left <= '9') {
			value += uint8_t((left - '0') * 16);
		} else {
			value += uint8_t((10 + (left - 'A')) * 16);
		}

		if (right >= '0' && right <= '9') {
			value += uint8_t(right - '0');
		} else {
			value += uint8_t(10 + (right - 'A'));
		}

		return value;
	}
} // namespace

namespace mango::memscn {
	// ex: "AA ? BB CC ? ? DD"
	//     "aa ? bb cc ? ? dd"
	//     "aa?bbcc??dd"
	Pattern::Pattern(const std::string_view pattern) {
		for (size_t i(0); i < pattern.size(); ++i) {
			// ignore whitespace
			if (pattern[i] == ' ')
				continue;

			if (pattern[i] == '?') {
				// wildcard
				this->m_data.push_back(uint16_t(-1));
			} else if (pattern.size() > i + 1) {
				// add the byte
				this->m_data.push_back(parse_byte(
					pattern[i], pattern[i + 1]));

				// skip the next character
				i += 1;
			}
		}
	}

	// code-style pattern
	// eg: "\xAA\x00\xBB\xCC\x00\x00\xDD" and "X?XX??X"
	//     "\xaa\x00\xbb\xcc\x00\x00\xdd" and "x?xx??x"
	Pattern::Pattern(const void* const pattern, const std::string_view mask) {
		const auto buffer = reinterpret_cast<const uint8_t*>(pattern);
		for (size_t i = 0; i < mask.size(); ++i) {
			if (mask[i] == '?') {
				// wiildcard
				this->m_data.push_back(uint16_t(-1));
			} else {
				this->m_data.push_back(uint16_t(buffer[i]));
			}
		}
	}

	// same as code-style pattern except the mask has no wildcards
	Pattern::Pattern(const void* const pattern, const size_t size) {
		const auto buffer = reinterpret_cast<const uint8_t*>(pattern);
		for (size_t i = 0; i < size; ++i)
			this->m_data.push_back(uint16_t(buffer[i]));
	}

	// does pattern match?
	bool Pattern::matches(const uint8_t* buffer) const {
		for (const auto b : this->m_data) {
			const auto value = *(buffer++);

			// wildcard
			if (b == uint16_t(-1))
				continue;

			// doesn't match
			if (uint8_t(b) != value)
				return false;
		}

		return true;
	}

	// search the memory for the provided pattern
	std::vector<uintptr_t> find(const Process& process, 
		const Pattern& pattern, const Range& range, const Filter& filter) 
	{
		// to deal with unsigned overflow
		const auto rangeend = range.start + 
			std::min(range.size, uintptr_t(-1) - range.start);

		uintptr_t address = range.start;
		std::vector<uintptr_t> matching;

		// iterate through each memory region
		MEMORY_BASIC_INFORMATION info;
		while (sizeof(info) == VirtualQueryEx(process.get_handle(),
			reinterpret_cast<void*>(address), &info, sizeof(info))) 
		{
			address = uintptr_t(info.BaseAddress) + info.RegionSize;

			// useless to us, skip
			if (info.State != MEM_COMMIT || info.Protect & PAGE_GUARD || info.Protect & PAGE_NOACCESS)
				continue;

			// ignore filtered areas
			if (!filter(info.Protect))
				continue;

			const auto blockstart = std::max(uintptr_t(info.BaseAddress), range.start);
			const auto blocksize = std::min(rangeend, address) - blockstart;

			// impossible for pattern to be in the memory
			if (blocksize < pattern.size())
				continue;

			// read the memory
			const auto buffer = std::make_unique<uint8_t[]>(blocksize);
			process.read(blockstart, buffer.get(), blocksize);

			// checking for matching pattern
			for (uintptr_t i = 0; i < blocksize - pattern.size(); ++i)
				if (pattern.matches(&buffer[i]))
					matching.push_back(blockstart + i);

			// we dont care about anything after this
			if (address >= rangeend)
				return matching;
		}

		return matching;
	}
	std::vector<uintptr_t> find(const Process& process, const Pattern& pattern,
		const std::string_view modulename, const Filter& filter) 
	{
		// scan from the modulebase to the modulebase + size
		if (const auto m(process.get_module(modulename)); m) {
			return find(process, pattern, Range{
				.start = m->get_image_base(),
				.size = m->get_image_size() }, filter);
		}

		throw FailedToFindModule();
	}

	// overload << operator
	std::ostream& operator<<(std::ostream& stream, const Pattern& pattern) {
		stream << "[ ";

		// output every byte in a pretty format
		for (const auto b : pattern.m_data) {
			if (b == uint16_t(-1)) {
				// wildcard
				stream << "? ";
			} else {
				// hex, uppercase, left padded with 0s
				stream << "0x" << std::setfill('0') << std::setw(2) << std::uppercase << std::hex << +b << ' ';
			}
		}

		stream << ']';
		return stream;
	}
	std::wostream& operator<<(std::wostream& stream, const Pattern& pattern) {
		stream << L"[ ";

		// output every byte in a pretty format
		for (const auto b : pattern.m_data) {
			if (b == uint16_t(-1)) {
				// wildcard
				stream << L"? ";
			} else {
				// hex, uppercase, left padded with 0s
				stream << L"0x" << std::setfill(L'0') << std::setw(2) << std::uppercase << std::hex << +b << L' ';
			}
		}

		stream << L']';
		return stream;
	}
} // namespace mango::memscn