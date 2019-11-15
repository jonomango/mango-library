#include <epic/loader.h>
#include <epic/process.h>
#include <epic/pattern_scanner.h>
#include <epic/shellcode.h>
#include <epic/vmt_hook.h>
#include <epic/iat_hook.h>
#include <epic/syscalls.h>
#include <epic/syscall_hook.h>
#include <epic/unused_memory.h>
#include <epic/windows_defs.h>
#include <misc/vector.h>
#include <misc/logger.h>
#include <misc/error_codes.h>
#include <misc/math.h>
#include <misc/fnv_hash.h>
#include <crypto/string_encryption.h>

#include "unit_tests.h"

#include <thread>
#include <sstream>
#include <fstream>

// TODO:
// std::source_location in exceptions when c++20 comes out
// improve manual mapper (apischema + tls callbacks + exceptions)

// setup logger channels
void setup_logger(std::ostream& stream = std::cout) {
	static const auto display_info = [&](const uint16_t attribute, const std::string_view prefix, std::ostringstream&& ss) {
		static const auto handle = GetStdHandle(STD_OUTPUT_HANDLE);

		stream << '[';
		SetConsoleTextAttribute(handle, attribute);
		stream << prefix;
		SetConsoleTextAttribute(handle, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
		stream << "] " << ss.str() << std::endl;
	};

	// info channel
	mango::logger.set_info_channel([](std::ostringstream&& ss) {
		display_info(FOREGROUND_BLUE | FOREGROUND_GREEN, "info", std::move(ss));
	});

	// success channel
	mango::logger.set_success_channel([](std::ostringstream&& ss) {
		display_info(FOREGROUND_GREEN, "success", std::move(ss));
	});

	// error channel
	mango::logger.set_error_channel([](std::ostringstream&& ss) {
		display_info(FOREGROUND_RED, "error", std::move(ss));
	});

	mango::logger.success("Logging channels initialized.");
}

class DriverInterface {
public:
	struct SetupOptions {
		// dwDesiredAccess
		uint32_t m_access = GENERIC_READ | GENERIC_WRITE;

		// dwFlagsAndAttributes
		uint32_t m_attributes = FILE_ATTRIBUTE_NORMAL;
	};

public:
	DriverInterface() = default;
	DriverInterface(const std::string& name, const SetupOptions& options = SetupOptions()) {
		this->setup(name, options);
	}
	~DriverInterface() { this->release(); }

	// open a handle to the driver
	void setup(const std::string& name, const SetupOptions& options = SetupOptions()) {
		this->release();

		// open handle
		this->m_handle = CreateFileA(name.c_str(), options.m_access, 0, nullptr, OPEN_EXISTING, options.m_attributes, nullptr);
		if (this->m_handle == INVALID_HANDLE_VALUE)
			throw mango::MangoError("Invalid driver handle.");

		this->m_is_valid = true;
	}

	// close the handle to the driver
	void release() {
		if (!this->m_is_valid)
			return;

		CloseHandle(this->m_handle);
		this->m_is_valid = false;
	}

	// write operation
	uint32_t write(const void* const buffer, const uint32_t size) const {
		DWORD num_bytes_written = 0;
		if (!WriteFile(this->m_handle, buffer, size, &num_bytes_written, nullptr))
			throw mango::MangoError("Failed to write to driver.");
		return num_bytes_written;
	}

	// read operation
	uint32_t read(void* const buffer, const uint32_t size) const {
		DWORD num_bytes_read = 0;
		if (!ReadFile(this->m_handle, buffer, size, &num_bytes_read, nullptr))
			throw mango::MangoError("Failed to read from driver.");
		return num_bytes_read;
	}

	// if class is not setup or has been released
	bool is_valid() const noexcept { return this->m_is_valid; }

	// get the underlying win32 handle
	HANDLE get_handle() const noexcept { return this->m_handle; }

private:
	HANDLE m_handle = nullptr;
	bool m_is_valid = false;
};

int main() {
	setup_logger();

	// in case we broke some shit
	run_unit_tests();

	// catch c++ exceptions
	try {
		const DriverInterface driver("\\\\.\\ExampleSymLink");
		mango::logger.info("Success! Driver handle: ", driver.get_handle());

		struct WriteInfo {
			int m_magic_number = 69;
		} buffer;

		driver.write(&buffer, sizeof(buffer));
		driver.read(&buffer, sizeof(buffer));
	} catch (mango::MangoError& e) {
		mango::logger.error(e.full_error());
	}

	mango::logger.info("program end");
	std::getchar();
	return 0;
}