#include "../../include/epic/shellcode.h"

#include <iomanip>

#include "../../include/epic/process.h"


namespace mango {
	// allocate memory in the target process and write shellcode to the address
	uintptr_t Shellcode::allocate(const Process& process) const {
		const auto address = process.alloc_virt_mem(this->m_data.size(), PAGE_EXECUTE_READWRITE);
		process.write(address, this->m_data.data(), this->m_data.size());
		return address;
	}

	// free shellcode that was previously allocated with Shellcode::allocate()
	// NOTE: do not modify (.push or .clear) shellcode between allocate() and free() calls
	void Shellcode::free(const Process& process, const uintptr_t address) const {
		process.free_virt_mem(address);
	}

	// execute the shellcode in the process, basically just calls
	// Shellcode::allocate(), Process::create_remote_thread(), Shellcode::free()
	void Shellcode::execute(const Process& process) const {
		const auto address = this->allocate(process);
		process.create_remote_thread(address);
		this->free(process, address);
	}

	// lets you do stuff like std::cout << shellcode << std::endl;
	std::ostream& operator<<(std::ostream& stream, const Shellcode& shellcode) {
		stream << "[ ";

		// output every byte in a pretty format
		for (const uint8_t b : shellcode.get_data())
			// hex, uppercase, left padded with 0s
			stream << "0x" << std::setfill('0') << std::setw(2) << std::uppercase << std::hex << +b << ' ';

		stream << "]";

		return stream;
	}
	std::wostream& operator<<(std::wostream& stream, const Shellcode& shellcode) {
		stream << L"[ ";

		// output every byte in a pretty format
		for (const uint8_t b : shellcode.get_data())
			// hex, uppercase, left padded with 0s
			stream << L"0x" << std::setfill(L'0') << std::setw(2) << std::uppercase << std::hex << +b << L' ';

		stream << L"]";
		return stream;
	}
} // namespace mango