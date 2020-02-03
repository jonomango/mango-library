#pragma once

#include "shellcode_wrappers.h"
#include "../misc/memory_allocator.h"
#include "../misc/misc.h"
#include "../misc/math.h"

#include <vector>
#include <array>
#include <ostream>
#include <iostream>
#include <assert.h>


namespace mango {
	class Process;

	class Shellcode {
	public:
		using ShellcodeData = std::vector<uint8_t>;

	public:
		Shellcode() = default;

		// same as Shellcode s(); s.push(args);
		template <typename ...Args>
		explicit Shellcode(Args&& ...args) noexcept { this->push(std::forward<Args>(args)...);  }

		// allow copying
		Shellcode(Shellcode&) = default;
		Shellcode& operator=(Shellcode&) = default;

		// allow moving
		Shellcode(Shellcode&& other) noexcept { *this = std::move(other); }
		Shellcode& operator=(Shellcode&& other) {
			this->m_data = std::move(other.m_data);
			return *this;
		}

		// allocate memory in the target process
		uintptr_t allocate(const Process& process) const;

		// copy the shellcode to the address
		void write(const Process& process, const uintptr_t address) const;

		// allocate() then write()
		uintptr_t allocate_and_write(const Process& process) const {
			const auto address(this->allocate(process));
			this->write(process, address);
			return address;
		}
		uintptr_t allocate_and_write(const Process& process, MemoryAllocator& allocator) const {
			const auto address(allocator.allocate(this->m_data.size()));
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

		// same thing as above but uses allocator.allocate() and doesn't call Shellcode::free()
		void execute(const Process& process, MemoryAllocator& allocator, const uintptr_t argument = 0) const;

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
			(this->push(std::forward<Args>(args)), ...);
			return *this;
		}

		template <typename Ret>
		Shellcode& push(Ret&& value) noexcept {
			using Type = std::remove_const_t<std::remove_reference_t<Ret>>;

			// size before we add shibble
			const auto old_size(this->m_data.size());

			// for integral types
			if constexpr (std::is_integral_v<Type>) {
				// resize
				this->m_data.resize(this->m_data.size() + sizeof(value));

				// copy
				*reinterpret_cast<Type*>(this->m_data.data() + old_size) = value;
			} else if constexpr (std::is_same_v<Type, Shellcode>) {
				const auto length(value.m_data.size());

				// resize
				this->m_data.resize(this->m_data.size() + length);

				// copy into this->m_data
				memcpy_s(this->m_data.data() + old_size, length, value.m_data.data(), length);
			} else if constexpr (std::is_same_v<Type, StringWrapper>) {
				const auto length(value.size());

				// resize
				this->m_data.resize(this->m_data.size() + length);

				// copy into this->m_data
				memcpy_s(this->m_data.data() + old_size, length, value.string(), length);
			} else if constexpr ((std::is_array_v<Type> || Shellcode::is_stdcontainer<Type>::value) && sizeof(value[0]) == 1) { // byte arrays
				auto length(sizeof(value) - 1);
				const void* data(&value);
				if constexpr (Shellcode::is_stdcontainer<Type>::value) {
					length = value.size();
					data = value.data();
				}

				// resize
				this->m_data.resize(this->m_data.size() + length);

				// copy into this->m_data
				memcpy_s(this->m_data.data() + old_size, length, data, length);
			} else { // other types
				static_assert(false, "Type not supported");
			}

			// for chaining
			return *this;
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