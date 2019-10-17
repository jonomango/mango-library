#pragma once

#include <string>
#include <array>
#include <algorithm>

#include "../misc/misc.h"
#include "compile_time_key.h"

#undef max

// kinda sucks that we have to use a macro but whatever
#define encrypt_str(str)\
([]() {\
	constexpr auto _encrypted = mango::EncryptedString(str);\
	mango::force_compile_time<uint64_t, _encrypted.ensure_compile_time()>();\
	return _encrypted();\
})()


namespace mango {
	template <size_t Size>
	class EncryptedString {
	public:
		// encrypt the string in the constructor, at compile time (hopefully)
		constexpr EncryptedString(const char(&str)[Size]) : m_key(compile_time_key(Size)) {
			for (size_t i = 0; i < Size; i += 8) {
				const auto block = this->pack_block(str + i, Size - i);

				// encrypt the block
				this->m_data[i / 8] = this->enc_block(block, i);
			}
		}

		// ensures that the string is created at compile time.
		// usage: force_compile_time<uint64_t, e.ensure_compile_time()>()
		constexpr uint64_t ensure_compile_time() const {
			return this->m_data[(Size - 1) / 8];
		}

		// decrypt the string
		std::string operator()() const {
			std::string str(Size, 0);
			for (size_t i = 0; i < Size; i += 8) {
				// decrypt the block
				const auto block = this->dec_block(this->m_data[i / 8], i);

				// unpack the block
				for (size_t j = 0; j < std::min<size_t>(Size - i, 8); ++j)
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
		static_assert(Size > 0, "Cannot encrypt empty string");

	private:
		std::array<uint64_t, (Size + 7) / 8> m_data;
		uint64_t m_key;
	};
} // namespace mango