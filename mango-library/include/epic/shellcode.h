#pragma once

#include <vector>
#include <array>
#include <ostream>


namespace mango {
	class Process;

	class Shellcode {
	public:
		using ShellcodeData = std::vector<uint8_t>;

	public:
		Shellcode() = default;

		// same as Shellcode s(); s.push(args);
		template <typename ...Args>
		Shellcode(const Args... args) { this->push(args...); }

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
		void push(const Args... args) {
			// kinda a code hack but whatever /shrug
			const int _unused[] = { 0, (this->push(args), 0)... };
		}

		// for integral types (ints, bytes, ...)
		template <typename T>
		void push(const T value) {
			static_assert(std::is_integral<T>::value, "type not supported");
			
			// could use a loop instead but this is probably faster
			const auto old_size = this->m_data.size();
			this->m_data.resize(this->m_data.size() + sizeof(value));
			*reinterpret_cast<T*>(this->m_data.data() + old_size) = value;
		}

		// c-strings
		void push(const char* const str);

	private:
		ShellcodeData m_data;
	};

	// lets you do stuff like std::cout << shellcode << std::endl;
	std::ostream& operator<<(std::ostream& stream, const Shellcode& shellcode);
} // namespace mango