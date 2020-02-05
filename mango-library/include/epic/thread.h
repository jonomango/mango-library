#pragma once

#include "windows_defs.h"

#include <functional>
#include <stdint.h>


namespace mango {
	// TODO: add suspend/resume + context getters/setters + priority getter + time spent running
	class Thread {
	public:
		struct SetupOptions {
			// this will be passed to OpenThread
			uint32_t handle_access = THREAD_ALL_ACCESS;
		};

	public:
		Thread() = default; // left in an invalid state
		explicit Thread(const uint32_t threadid, const SetupOptions& options = SetupOptions()) {
			this->setup(threadid, options);
		}

		~Thread() { this->release(); }

		// prevent copying
		Thread(const Thread&) = delete;
		Thread& operator=(const Thread&) = delete;

		// allow moving
		Thread(Thread&& other) { *this = std::move(other); }
		Thread& operator=(Thread&& other) noexcept {
			this->release();
			this->m_is_valid = other.m_is_valid;
			this->m_handle = other.m_handle;
			this->m_tid = other.m_tid;
			other.m_is_valid = false;
			return *this;
		}

		// setup by thread id
		void setup(const uint32_t threadid, const SetupOptions& options = SetupOptions());

		// clean up
		void release() noexcept;

		// if Thread is not valid, any operations on it are undefined behavior
		bool is_valid() const noexcept { return this->m_is_valid; }

		// get the raw win32 thread handle
		HANDLE get_handle() const noexcept { return this->m_handle; }

		// get the thread id
		uint32_t get_tid() const noexcept { return this->m_tid; }

		// the unix timestamp of when the thread was created
		uint64_t get_creation_time() const;

		// thread's start address
		uintptr_t get_start_address(const bool is64bit) const;

	private:
		bool m_is_valid = false;
		HANDLE m_handle = nullptr;
		uint32_t m_tid = 0;
	};
} // namespace mango