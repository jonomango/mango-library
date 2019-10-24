#pragma once

#include <string>
#include <array>
#include <algorithm>

#include "compile_time_key.h"

// windows
#undef min

// kinda sucks that we have to use a macro but whatever
#define encrypt_string(str)\
(([]() {\
	constexpr auto _encrypted = mango::_EncryptedString(str);\
	return _encrypted();\
})())


namespace mango { 
	// compile time block based string encryption
	template <size_t Size>
	class _EncryptedString {
	public:
		// encrypt the string in the constructor, at compile time (hopefully)
		constexpr _EncryptedString(const char(&str)[Size]) : m_key(compile_time_key(Size - 1)) {
			const auto size = Size - 1;
			for (size_t i = 0; i < size; i += 8) {
				const auto block = this->pack_block(str + i, size - i);

				// encrypt the block
				this->m_data[i / 8] = this->enc_block(block, i);
			}
		}

		// decrypt the string
		std::string operator()() const {
			const auto size = Size - 1;
			std::string str(size, 0);
			for (size_t i = 0; i < size; i += 8) {
				// decrypt the block
				const auto block = this->dec_block(this->m_data[i / 8], i);

				// unpack the block
				for (size_t j = 0; j < std::min<size_t>(size - i, 8); ++j)
					str[i + j] = uint8_t(block >> (j * 8));
			}
			return str;
		}

	private:
		// encrypt a block
		constexpr uint64_t enc_block(const uint64_t block, const size_t i) const {
			return (block + (this->m_key * i)) ^ (this->m_key + i);
		};

		// decrypt a block
		constexpr uint64_t dec_block(const uint64_t block, const size_t i) const {
			return (block ^ (this->m_key + i)) - (this->m_key * i);
		};

		// pack into 64bits
		constexpr uint64_t pack_block(const char* str, const size_t size) const {
			uint64_t block = 0;
			for (size_t i = 0; i < std::min<size_t>(size, 8); ++i)
				block += uint64_t(str[i]) << (i * 8);
			return block;
		}

		// atleast 1 char
		static_assert(Size > 1, "Cannot encrypt empty string");

	private:
		std::array<uint64_t, (Size + 6) / 8> m_data;
		uint64_t m_key;
	};
} // namespace mango