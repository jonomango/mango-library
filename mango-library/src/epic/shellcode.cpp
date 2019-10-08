#include <epic/shellcode.h>

#include <iomanip>

#include <epic/process.h>


namespace mango {
	void* Shellcode::allocate(const Process& process) const {
		const auto address = process.alloc_virt_mem(this->m_data.size(), PAGE_EXECUTE_READWRITE);
		process.write(address, this->m_data.data(), this->m_data.size());
		return address;
	}
	void Shellcode::free(const Process& process, void* const address) const {
		process.free_virt_mem(address, this->m_data.size());
	}
	void Shellcode::execute(const Process& process) const {
		const auto address = this->allocate(process);
		process.create_remote_thread(address);
		this->free(process, address);
	}

	void Shellcode::push(const char* const str) {
		const auto length = strlen(str);
		const auto old_size = this->m_data.size();

		// copy
		this->m_data.resize(this->m_data.size() + length);
		memcpy_s(this->m_data.data() + old_size, length, str, length);
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
} // namespace mango