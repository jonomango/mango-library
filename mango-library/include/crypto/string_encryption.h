#pragma once

#include <string>
#include <array>
#include <algorithm>

#include "compile_time_key.h"
#include "../misc/misc.h"

// windows
#undef min

// kinda sucks that we have to use a macro but whatever
#define enc_str(str)\
(([]() {\
	constexpr mango::_EncryptedString<sizeof(str)> _encrypted_str(str);\
	return _encrypted_str();\
})())\


namespace mango { 
	// compile time block based string encryption
	template <size_t Size>
	class _EncryptedString {
	public:
		// encrypt the string in the constructor, at compile time (hopefully)
		explicit constexpr _EncryptedString(const char(&str)[Size]) : m_key(compile_time_key(Size - 1)), m_data({}) {
			// pack the string into 64-bit blocks
			const auto size = Size - 1;
			for_constexpr<0, Size - 1, 1>([&](const size_t i) {
				if (i % 8 == 0)
					this->m_data[i / 8] = 0;
				this->m_data[i / 8] += uint64_t(str[i]) << ((i % 8) * 8);
			});

			// encrypt each block
			for_constexpr<0, (Size + 6) / 8, 1>([&](const size_t i) {
				this->m_data[i] = (this->m_data[i] + (this->m_key * i)) ^ (this->m_key + i);
			});
		}

		// decrypt the string
		std::string operator()() const {
			const auto size = Size - 1;
			std::string decrypted_string(size, 0);
			for (size_t i = 0; i < size; i += 8) {
				// decrypt the block
				const auto block = this->dec_block(this->m_data[i / 8], i / 8);

				// unpack the block
				for (size_t j = 0; j < std::min<size_t>(size - i, 8); ++j)
					decrypted_string[i + j] = uint8_t(block >> (j * 8));
			}

			return decrypted_string;
		}

	private:
		// decrypt a block
		constexpr uint64_t dec_block(const uint64_t block, const size_t i) const {
			return (block ^ (this->m_key + i)) - (this->m_key * i);
		};

		// atleast 1 char
		static_assert(Size > 1, "Cannot encrypt empty string");

	private:
		std::array<uint64_t, (Size + 6) / 8> m_data;
		const uint64_t m_key;
	};
} // namespace mango