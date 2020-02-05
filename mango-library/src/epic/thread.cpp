#include "../../include/epic/thread.h"

#include "../../include/misc/error_codes.h"


namespace mango {
	// setup by thread id
	void Thread::setup(const uint32_t threadid, const SetupOptions& options) {
		this->release();

		// get a handle to the thread
		this->m_handle = OpenThread(options.handle_access, FALSE, threadid);
		if (!this->m_handle)
			throw InvalidThreadHandle(mango_format_w32status(GetLastError()));

		this->m_tid = threadid;
		this->m_is_valid = true;
	}

	// clean up
	void Thread::release() noexcept {
		if (this->m_is_valid) try {
			this->m_is_valid = false;
			CloseHandle(this->m_handle);
		} catch (...) {};
	}

	// the unix timestamp of when the thread was created
	uint64_t Thread::get_creation_time() const {
		FILETIME creation, exit, kernel, user;
		GetThreadTimes(this->m_handle, &creation, &exit, &kernel, &user);

		// could do some bitshifting instead ig
		LARGE_INTEGER time{ .LowPart = creation.dwLowDateTime, 
			.HighPart = LONG(creation.dwHighDateTime) };

		// convert to milliseconds
		time.QuadPart /= 10000;

		// convert to unix time
		time.QuadPart -= 11644473600000;

		return time.QuadPart;
	}

	// thread's start address
	uintptr_t Thread::get_start_address(const bool is64bit) const {
		NTSTATUS status = 0;
		uintptr_t startaddress = 0;

		// TODO: find a way to dynamically check the thread's bitness (quickly too)
		if (is64bit) {
			status = windows::NtQueryInformationThread(this->m_handle,
				windows::ThreadQuerySetWin32StartAddress, &startaddress, 8, nullptr);
		} else {
			status = windows::NtQueryInformationThread(this->m_handle,
				windows::ThreadQuerySetWin32StartAddress, &startaddress, 4, nullptr);
		}
		
		// check for errors (usually caused by wrong bitness)
		if (NT_ERROR(status))
			throw FailedToGetThreadStartAddress(mango_format_ntstatus(status));

		return startaddress;
	}
} // namespace mango