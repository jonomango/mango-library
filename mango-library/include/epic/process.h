#pragma once

#include <stdint.h>
#include <optional>
#include <string>

#include <Windows.h>
#include <winternl.h>


namespace mango {
	// RAII
	class Process {
	public:
		Process(); // this uses the current process pid
		Process(const uint32_t pid);

		// clean up
		~Process();

		// if Process is not valid, any operations on it are undefined behavior
		bool is_valid() const { return this->m_is_valid; }

		// if the Process is itself
		bool is_self() const { return this->m_is_self; }

		// check if process is 64 or 32 bit
		bool is_64bit() const;

		// read from a memory address
		void read(const void* const address, void* const buffer, const size_t size) const;

		// easy-to-use wrapper for read()
		template <typename T> T read(const void* const address) const {
			T buffer;
			this->read(address, &buffer, sizeof(buffer));
			return buffer;
		}
		template <typename T> T read(const uintptr_t address) const {
			return this->read<T>(reinterpret_cast<const void* const>(address));
		}

		// write to a memory address
		void write(void* const address, const void* const buffer, const size_t size) const;

		// easy-to-use wrapper for write()
		template <typename T> void write(void* const address, const T& value) const {
			this->write(address, &value, sizeof(value));
		}
		template <typename T> void write(const uintptr_t address, const T& value) const {
			this->write<T>(reinterpret_cast<void* const>(address), value);
		}

		// allocate virtual memory in the process (wrapper for VirtualAllocEx)
		void* alloc_virt_mem(const size_t size, 
			const uint32_t protection = PAGE_READWRITE, 
			const uint32_t type = MEM_COMMIT | MEM_RESERVE) const;

		// free virtual memory in the process (wrapper for VirtualFreeEx)
		void free_virt_mem(void* const address, const size_t size, 
			const uint32_t type = MEM_DECOMMIT | MEM_RELEASE) const;

		// get the underlying handle that is used for operations such as reading and writing
		HANDLE get_handle() const { return this->m_handle; }

		// the pid of the process (supplied in construction)
		uint32_t get_pid() const { return this->m_pid; }

		// get the name of the process
		std::string get_name() const;

		// get the PEB structure
		std::optional<PEB> get_peb() const;

	public:
		// a more intuitive way to test for validity
		explicit operator bool() const { return this->is_valid(); }

		// prevent copying
		Process(const Process&) = delete;
		Process& operator=(const Process&) = delete;

	private:
		bool m_is_valid = false,
			m_is_self = false;
		HANDLE m_handle = nullptr;
		uint32_t m_pid = 0;
	};
} // namespace mango