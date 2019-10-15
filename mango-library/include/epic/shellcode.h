#pragma once

#include <vector>
#include <array>
#include <ostream>
#include <iostream>


namespace mango {
	class Process;

	class Shellcode {
	public:
		using ShellcodeData = std::vector<uint8_t>;

	public:
		Shellcode() = default;

		// same as Shellcode s(); s.push(args);
		template <typename ...Args>
		Shellcode(Args&& ...args) { this->push(std::forward<Args>(args)...);  }

		// allocate memory in the target process and write shellcode to the address
		void* allocate(const Process& process) const;

		// free shellcode that was previously allocated with Shellcode::allocate()
		// NOTE: do not modify shellcode between allocate() and free() calls
		void free(const Process& process, void* const address) const;

		// run the shellcode in the process, basically just calls
		// Shellcode::allocate(), Process::create_remote_thread(), Shellcode::free()
		void execute(const Process& process) const;

		// reset
		void clear() { this->m_data.clear(); }

		// get the raw bytes
		const ShellcodeData& get_data() const { return this->m_data; }
		ShellcodeData& get_data() { return this->m_data; }

		// catch-all function
		template <typename ...Args>
		void push(Args&& ...args) {
			// kinda a hack but whatever /shrug
			const int _unused[] = { (this->push(std::forward<Args>(args)), 0)... };
		}

		template <typename T>
		void push(T&& value) {
			using Type = std::remove_const_t<std::remove_reference_t<T>>;

			// for integral types
			if constexpr (std::is_integral_v<Type>) {
				// resize
				const auto old_size = this->m_data.size();
				this->m_data.resize(this->m_data.size() + sizeof(value));

				// copy
				*reinterpret_cast<Type*>(this->m_data.data() + old_size) = value;
			} else if constexpr (sizeof(value[0]) == 1 && std::is_array_v<Type>) { // byte arrays
				constexpr auto length = sizeof(value) - 1;

				// resize
				const auto old_size = this->m_data.size();
				this->m_data.resize(this->m_data.size() + length);

				// copy into this->m_data
				memcpy_s(this->m_data.data() + old_size, length, &value, length);
			} else { // other types
				static_assert(false, "Only integral types or byte arrays allowed");
			}
		}

	private:
		ShellcodeData m_data;
	};

	// lets you do stuff like std::cout << shellcode << std::endl;
	std::ostream& operator<<(std::ostream& stream, const Shellcode& shellcode);
	std::wostream& operator<<(std::wostream& stream, const Shellcode& shellcode);
} // namespace mango