#pragma once

#include <vector>
#include <array>
#include <ostream>
#include <iostream>
#include <assert.h>

#include "../misc/misc.h"
#include "../misc/math.h"


namespace mango {
	class Process;

	class Shellcode {
	public:
		using ShellcodeData = std::vector<uint8_t>;

	public:
		Shellcode() = default;

		// same as Shellcode s(); s.push(args);
		template <typename ...Args>
		Shellcode(Args&& ...args) noexcept { this->push(std::forward<Args>(args)...);  }

		// allocate memory in the target process
		uintptr_t allocate(const Process& process) const;

		// copy the shellcode to the address
		void write(const Process& process, uintptr_t address) const;

		// allocate() then write()
		uintptr_t allocate_and_write(const Process& process) const {
			const auto address = this->allocate(process);
			this->write(process, address);
			return address;
		}

		// free shellcode that was previously allocated with Shellcode::allocate()
		// NOTE: do not modify (.push or .clear) shellcode between allocate() and free() calls
		static void free(const Process& process, const uintptr_t address);

		// execute the shellcode in the process, basically just calls
		// Shellcode::allocate_and_write()
		// Process::create_remote_thread()
		// Shellcode::free()
		void execute(const Process& process, const uintptr_t argument = 0) const;

		// reset
		void clear() noexcept { this->m_data.clear(); }

		// amount of bytes
		size_t size() noexcept { return this->m_data.size(); }

		// get the raw bytes
		const ShellcodeData& get_data() const noexcept { return this->m_data; }
		ShellcodeData& get_data() noexcept { return this->m_data; }

		// push raw data, used by push()
		Shellcode& push_raw(const void* const data, const size_t size);

		// catch-all function
		template <typename ...Args>
		Shellcode& push(Args&& ...args) noexcept {
			// kinda a hack but whatever /shrug
			const int _unused[] = { (this->push(std::forward<Args>(args)), 0)... };
			return *this;
		}

		template <typename Ret>
		Shellcode& push(Ret&& value) noexcept {
			using Type = std::remove_const_t<std::remove_reference_t<Ret>>;

			// for integral types
			if constexpr (std::is_integral_v<Type>) {
				// resize
				const auto old_size = this->m_data.size();
				this->m_data.resize(this->m_data.size() + sizeof(value));

				// copy
				*reinterpret_cast<Type*>(this->m_data.data() + old_size) = value;
			} else if constexpr (std::is_same_v<Type, StringWrapper>) {
				const auto length = value.get_size();

				// resize
				const auto old_size = this->m_data.size();
				this->m_data.resize(this->m_data.size() + length);

				// copy into this->m_data
				memcpy_s(this->m_data.data() + old_size, length, value.get_str(), length);
			} else if constexpr ((std::is_array_v<Type> || is_stdcontainer<Type>::value) && sizeof(value[0]) == 1) { // byte arrays
				auto length = sizeof(value) - 1;
				const void* data = &value;
				if constexpr (is_stdcontainer<Type>::value) {
					length = value.size();
					data = value.data();
				}

				// resize
				const auto old_size = this->m_data.size();
				this->m_data.resize(this->m_data.size() + length);

				// copy into this->m_data
				memcpy_s(this->m_data.data() + old_size, length, data, length);
			} else { // other types
				static_assert(false, "Only integral types or byte arrays allowed");
			}

			// for chaining
			return *this;
		}

		// ret instruction, ret() or ret(bytes)
		static constexpr StringWrapper ret() { return "\xC3"; }
		static constexpr std::array<uint8_t, 3> ret(const uint16_t size) {
			return { uint8_t(0xC2), uint8_t(size), uint8_t(size >> 8) };
		}

		// start a stackframe
		template <bool is64bit = false>
		static constexpr StringWrapper prologue() {
			if constexpr (is64bit) {
				return "\x55\x48\x89\xE5";
			} else {
				return "\x55\x89\xE5";
			}
		}

		// end of a stackframe
		template <bool is64bit = false>
		static constexpr StringWrapper epilogue() {
			if constexpr (is64bit) {
				return "\x48\x89\xEC\x5D";
			} else {
				return "\x89\xEC\x5D";
			}
		}

		// shellcode to switch execution from x86 to x64
		static constexpr StringWrapper enter_x64() {
			return "\x6A\x33"          // push 0x33 (x64 code segment)
				"\xE8\x00\x00\x00\x00" // call +0x5 (basically just push eip and continue execution)
				"\x83\x04\x24\x05"     // add dword ptr [esp], 0x5
				"\xCB";                // retf
		}

		// shellcode to switch execution from x64 to x86
		static constexpr StringWrapper enter_x86() {
			return "\xE8\x00\x00\x00\x00"      // call +0x5 (basically just push rip and continue execution)
				"\xC7\x44\x24\x04\x23\x00\x00\x00" // mov dword ptr [rsp + 4], 0x23 (x86 code segment)
				"\x48\x83\x04\x24\x0E"         // add qword ptr [rsp], 0x0E
				"\xCB";                        // retf
		}

		// example output: "AAAABAAACAAA"
		template <size_t size, size_t block_size = 4>
		static constexpr std::array<uint8_t, size> cyclic() {
			static_assert(size > 0);
			static_assert(block_size > 0);
			static_assert(size % block_size == 0);

			std::array<uint8_t, size> data;
			for (size_t i = 0; i < size; i += block_size) {
				const auto current = i / block_size;
				for (size_t j = 0; j < block_size; ++j)
					data[i + j] = uint8_t('A' + (current / math::pow(26, j)) % 26);
			}

			return data;
		}

		// the offset from the start of a cyclic shellcode
		template <size_t block_size = 4>
		static constexpr uintptr_t cyclic_offset(const std::array<uint8_t, block_size>& value) {
			uintptr_t offset = 0;
			for (size_t i = 0; i < block_size; ++i)
				offset += uintptr_t(value[i] - 'A') * math::pow(26, i);
			return offset;
		}

		template <typename T>
		static constexpr uintptr_t cyclic_offset(T&& value) {
			uintptr_t offset = 0;
			for (size_t i = 0; i < sizeof(T); ++i)
				offset += uintptr_t(uint8_t(value >> (8 * i)) - 'A') * math::pow(26, i);
			return offset * sizeof(T);
		}

	private:
		template<class T>
		struct is_stdcontainer : std::false_type {};

		// std::array
		template<class T, std::size_t N>
		struct is_stdcontainer<std::array<T, N>> : std::true_type {};

		// std::vector
		template<class T>
		struct is_stdcontainer<std::vector<T>> : std::true_type {};

	private:
		ShellcodeData m_data;
	};

	// lets you do stuff like std::cout << shellcode << std::endl;
	std::ostream& operator<<(std::ostream& stream, const Shellcode& shellcode);
	std::wostream& operator<<(std::wostream& stream, const Shellcode& shellcode);
} // namespace mango