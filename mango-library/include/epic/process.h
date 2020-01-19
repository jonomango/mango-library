#pragma once

#include <stdint.h>
#include <string>
#include <string_view>
#include <unordered_map>

#include "windows_defs.h"
#include "loaded_module.h"
#include "../misc/misc.h"


namespace mango {
	class Process {
	public:
		struct HandleInfo {
			HANDLE handle;
			uint8_t type;
			ACCESS_MASK access;
		};

		using ReadMemoryFunc			= void (*)(const Process* process, const void* address, void* buffer, size_t size);
		using WriteMemoryFunc			= void (*)(const Process* process, void* address, const void* buffer, size_t size);
		using AllocateMemoryFunc		= void*(*)(const Process* process, size_t size, uint32_t protection, uint32_t type);
		using FreeMemoryFunc			= void (*)(const Process* process, void* address, size_t size, uint32_t type);
		using CreateRemoteThreadFunc	= void (*)(const Process* process, void* address, void* argument);

		// options used at setup
		struct SetupOptions {
			// lazy loading, only load modules when they are requested
			bool defer_module_loading = true;

			// the access mask to open the process with
			ACCESS_MASK handle_access = PROCESS_ALL_ACCESS;

			// user-defineable
			ReadMemoryFunc read_memory_func = default_read_memory_func;
			WriteMemoryFunc write_memory_func = default_write_memory_func;
			AllocateMemoryFunc allocate_memory_func = default_allocate_memory_func;
			FreeMemoryFunc free_memory_func = default_free_memory_func;
			CreateRemoteThreadFunc create_remote_thread_func = default_create_remote_thread_func;
		};

		// containers
		using ProcessHandles = std::vector<HandleInfo>;
		using ProcessModules = std::unordered_map<std::string, LoadedModule>;
		using ModuleAddressMap = std::unordered_map<std::string, uintptr_t>;

	public:
		Process() = default; // left in an invalid state
		explicit Process(const uint32_t pid, const SetupOptions& options = SetupOptions()) {
			this->setup(pid, options); 
		}
		explicit Process(const HANDLE handle, const SetupOptions& options = SetupOptions()) {
			this->setup(handle, options);
		}

		// just calls release
		~Process() noexcept { this->release(); }

		// get the current process
		static Process current(const SetupOptions& options = SetupOptions()) { 
			return Process(GetCurrentProcess(), options);
		}

		// SeDebugPrivilege
		static void set_debug_privilege(const bool value);

		// get a list of pids that match the process name
		static std::vector<uint32_t> get_pids_by_name(const std::string_view process_name);

		// setup by pid
		void setup(const uint32_t pid, const SetupOptions& options = SetupOptions());

		// setup using an existing handle (must have atleast PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
		void setup(const HANDLE handle, const SetupOptions& options = SetupOptions());

		// clean up
		void release() noexcept;

		// if Process is not valid, any operations on it are undefined behavior
		bool is_valid() const noexcept { return this->m_is_valid; }

		// if the Process is itself
		bool is_self() const noexcept { return this->m_is_self; }

		// process running under wow64
		bool is_wow64() const noexcept { return this->m_is_wow64; }

		// check if process is 64 or 32 bit
		bool is_64bit() const noexcept { return this->m_is_64bit; }

		// get the size of a pointer
		size_t get_ptr_size() const noexcept { return this->is_64bit() ? 8 : 4; }

		// get the underlying handle that the class wraps around
		HANDLE get_handle() const noexcept { return this->m_handle; }

		// the pid of the process (supplied in construction)
		uint32_t get_pid() const noexcept { return this->m_pid; }

		// get the name of the process
		std::string get_name() const noexcept { return this->m_process_name; }

		// get a list of loaded modules
		const ProcessModules& get_modules() const noexcept { return this->m_modules; }

		// get a loaded module, case-insensitive (passing "" for name returns the current process module)
		const LoadedModule* get_module(const std::string_view name = "") const;

		// get the base address of a module
		uintptr_t get_module_addr(const std::string_view module_name = "") const;

		// this uses the internal list of modules to find the function address (doesn't account for ApiSchema)
		uintptr_t get_proc_addr(const std::string_view module_name, const std::string_view func_name) const;

		// api name -> dll name
		std::string resolve_apiset(const std::string_view name) const;

		// peb structures
		PEB_M32 get_peb32() const;
		PEB_M64 get_peb64() const;
		uintptr_t get_peb32_addr() const;
		uintptr_t get_peb64_addr() const;

		// read from a memory address
		void read(const void* const address, void* const buffer, const size_t size) const;
		void read(const uintptr_t address, void* const buffer, const size_t size) const {
			this->read(reinterpret_cast<void*>(address), buffer, size);
		}

		// easy to use wrapper for read()
		template <typename T, typename Addr> 
		T read(const Addr address) const {
			T buffer; this->read(uintptr_t(address), &buffer, sizeof(buffer));
			return buffer;
		}

		// write to a memory address
		void write(void* const address, const void* const buffer, const size_t size) const;
		void write(const uintptr_t address, const void* const buffer, const size_t size) const {
			this->write(reinterpret_cast<void*>(address), buffer, size);
		}

		// easy to use wrapper for write()
		template <typename T, typename Addr> 
		void write(const Addr address, const T& value) const {
			this->write(uintptr_t(address), &value, sizeof(value));
		}

		// allocate virtual memory in the process (wrapper for VirtualAllocEx)
		void* alloc_virt_mem(const size_t size,
			const uint32_t protection = PAGE_READWRITE,
			const uint32_t type = MEM_COMMIT | MEM_RESERVE) const;

		// free virtual memory in the process (wrapper for VirtualFreeEx)
		void free_virt_mem(void* const address, const size_t size = 0, const uint32_t type = MEM_RELEASE) const;
		void free_virt_mem(const uintptr_t address, const size_t size = 0, const uint32_t type = MEM_RELEASE) const {
			this->free_virt_mem(reinterpret_cast<void*>(address), size, type);
		}

		// get the protection of a page of memory
		uint32_t get_mem_prot(void* const address) const;
		uint32_t get_mem_prot(const uintptr_t address) const {
			return this->get_mem_prot(reinterpret_cast<void*>(address));
		}

		// set the protection, returns the old protection
		uint32_t set_mem_prot(void* address, const size_t size, const uint32_t protection) const;
		uint32_t set_mem_prot(const uintptr_t address, const size_t size, const uint32_t protection) const {
			return this->set_mem_prot(reinterpret_cast<void*>(address), size, protection);
		}

		// wrapper over CreateRemoteThread (will wait infinitely for the thread to finish)
		void create_remote_thread(void* const address, void* const argument = nullptr) const;
		void create_remote_thread(const uintptr_t address, const uintptr_t argument = 0) const {
			this->create_remote_thread(reinterpret_cast<void*>(address), reinterpret_cast<void*>(argument));
		}

		// suspend/resume the process
		void suspend() const;
		void resume() const;

		// get the handles that the process currently has open
		ProcessHandles get_open_handles() const;

		// updates the internal list of modules
		void load_modules();

		// a more intuitive way to test for validity
		explicit operator bool() const { return this->is_valid(); }

		// prevent copying
		Process(const Process&) = delete;
		Process& operator=(const Process&) = delete;

	private:
		// get the name of the process (to cache it)
		std::string query_name() const;

		// wow64 process
		bool query_is_wow64() const;

		// check whether the process is 64bit or not (to cache it)
		bool query_is_64bit() const;

		// update the internal list of module addresses
		void query_module_addresses();

		// the address of the 64bit peb
		uintptr_t query_peb64_address() const;

		// used by setup()
		void setup_internal();

	public:
		// override to change internal behavior
		void set_read_memory_func(const ReadMemoryFunc& func) noexcept { this->m_options.read_memory_func = func; }
		void set_write_memory_func(const WriteMemoryFunc& func) noexcept { this->m_options.write_memory_func = func; }
		void set_allocate_memory_func(const AllocateMemoryFunc& func) noexcept { this->m_options.allocate_memory_func = func; }
		void set_free_memory_func(const FreeMemoryFunc& func) noexcept { this->m_options.free_memory_func = func; }
		void set_create_remote_thread_func(const CreateRemoteThreadFunc& func) noexcept { this->m_options.create_remote_thread_func = func; }

		// default functions
		static void  default_read_memory_func(const Process* const process, const void* const address, void* const buffer, const size_t size);
		static void  default_write_memory_func(const Process* const process, void* const address, const void* const buffer, const size_t size);
		static void* default_allocate_memory_func(const Process* const process, const size_t size, const uint32_t protection, const uint32_t type);
		static void  default_free_memory_func(const Process* const process, void* const address, const size_t size, const uint32_t type);
		static void  default_create_remote_thread_func(const Process* const process, void* const address, void* const argument);

	private:
		bool m_is_valid = false,
			m_is_self = false,
			m_is_wow64 = false,
			m_is_64bit = false,
			m_free_handle = false;
		std::string m_process_name;
		HANDLE m_handle = nullptr;
		uint32_t m_pid = 0;
		uintptr_t m_peb64_address = 0;
		SetupOptions m_options;
		ModuleAddressMap m_module_addresses;
		mutable ProcessModules m_modules; // mutable for deferred loading
	};
} // namespace mango