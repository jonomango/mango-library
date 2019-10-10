#pragma once

#include <stdint.h>
#include <optional>
#include <string>
#include <unordered_map>

#include <Windows.h>
#include <winternl.h>

#include <epic/pe_header.h>


namespace mango {
	// RAII
	class Process {
	public:
		using Module = PeHeader; // might change this later if too much overhead
		using ProcessModules = std::unordered_map<std::string, Module>;

	public:
		Process() : Process(GetCurrentProcessId()) {}
		Process(const uint32_t pid);

		// clean up
		~Process();

		// if Process is not valid, any operations on it are undefined behavior
		bool is_valid() const { return this->m_is_valid; }

		// if the Process is itself
		bool is_self() const { return this->m_is_self; }

		// check if process is 64 or 32 bit
		bool is_64bit() const;

		// get the underlying handle that is used for operations such as reading and writing
		HANDLE get_handle() const { return this->m_handle; }

		// the pid of the process (supplied in construction)
		uint32_t get_pid() const { return this->m_pid; }

		// get the name of the process
		std::string get_name() const { return this->m_process_name; }

		// get the PEB structure
		std::optional<PEB> get_peb() const;

		// get a list of loaded modules
		const ProcessModules& get_modules() const { return this->m_modules; }

		// get a loaded module, case-insensitive (passing "" for name returns the current process module)
		const Process::Module* get_module(std::string name) const;

		// read from a memory address
		void read(const void* const address, void* const buffer, const size_t size) const;
		void read(const uintptr_t address, void* const buffer, const size_t size) const {
			this->read(reinterpret_cast<void*>(address), buffer, size);
		}

		// easy-to-use wrapper for read()
		template <typename T, typename Addr> T read(Addr const address) const {
			T buffer; this->read(address, &buffer, sizeof(buffer));
			return buffer;
		}

		// write to a memory address
		void write(void* const address, const void* const buffer, const size_t size) const;
		void write(const uintptr_t address, const void* const buffer, const size_t size) const {
			this->write(reinterpret_cast<void*>(address), buffer, size);
		}

		// easy-to-use wrapper for write()
		template <typename T, typename Addr> void write(Addr const address, const T& value) const {
			this->write(address, &value, sizeof(value));
		}

		// allocate virtual memory in the process (wrapper for VirtualAllocEx)
		void* alloc_virt_mem(const size_t size,
			const uint32_t protection = PAGE_READWRITE,
			const uint32_t type = MEM_COMMIT | MEM_RESERVE) const;

		// free virtual memory in the process (wrapper for VirtualFreeEx)
		void free_virt_mem(void* const address, const size_t size, 
			const uint32_t type = MEM_RELEASE) const;
		void free_virt_mem(const uintptr_t address, const size_t size,
			const uint32_t type = MEM_RELEASE) const {
			this->free_virt_mem(reinterpret_cast<void*>(address), size, type);
		}

		// get the protection of a page of memory
		uint32_t get_mem_prot(const void* const address) const;
		uint32_t get_mem_prot(const uintptr_t address) const {
			return this->get_mem_prot(reinterpret_cast<void*>(address));
		}

		// set the protection, returns the old protection
		uint32_t set_mem_prot(void* const address, const size_t size, const uint32_t protection) const;
		uint32_t set_mem_prot(const uintptr_t address, const size_t size, const uint32_t protection) const {
			return this->set_mem_prot(reinterpret_cast<void*>(address), size, protection);
		}

		// same as GetProcAddress()
		uintptr_t get_proc_addr(const std::string& module_name, const std::string& func_name) const;

		// wrapper over CreateRemoteThread
		void create_remote_thread(const void* const address) const;
		void create_remote_thread(const uintptr_t address) const { 
			this->create_remote_thread(reinterpret_cast<void*>(address)); 
		}

		// updates the internal list of modules
		void update_modules();

		// a more intuitive way to test for validity
		explicit operator bool() const { return this->is_valid(); }

		// prevent copying
		Process(const Process&) = delete;
		Process& operator=(const Process&) = delete;

	private:
		// get the name of the process (to cache it)
		std::string query_name() const;

	private:
		bool m_is_valid = false,
			m_is_self = false;
		HANDLE m_handle = nullptr;
		uint32_t m_pid = 0;
		Module m_process_module;
		ProcessModules m_modules;
		std::string m_process_name;
	};
} // namespace mango