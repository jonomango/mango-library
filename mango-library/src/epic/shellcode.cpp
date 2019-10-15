#include "../../include/epic/shellcode.h"

#include <iomanip>

#include "../../include/epic/process.h"


namespace mango {
	void* Shellcode::allocate(const Process& process) const {
		const auto address = process.alloc_virt_mem(this->m_data.size(), PAGE_EXECUTE_READWRITE);
		process.write(address, this->m_data.data(), this->m_data.size());
		return address;
	}
	void Shellcode::free(const Process& process, void* const address) const {
		process.free_virt_mem(address);
	}
	void Shellcode::execute(const Process& process) const {
		const auto address = this->allocate(process);
		process.create_remote_thread(address);
		this->free(process, address);
	}

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