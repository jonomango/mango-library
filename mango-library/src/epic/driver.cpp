#include "../../include/epic/driver.h"

#include "../../include/misc/error_codes.h"
#include "../../include/misc/scope_guard.h"


namespace mango {
	// open a handle to the driver
	void Driver::setup(const std::string_view name, const SetupOptions& options) {
		this->release();

		// std::string_view **could** be not null-terminated
		const std::string null_terminated_name{ name };

		// open handle
		this->m_handle = CreateFileA(null_terminated_name.c_str(), options.access, 0, nullptr, OPEN_EXISTING, options.attributes, nullptr);
		if (this->m_handle == INVALID_HANDLE_VALUE)
			throw InvalidFileHandle{ mango_format_w32status(GetLastError()) };

		this->m_is_valid = true;
	}

	// close the handle to the driver
	void Driver::release() noexcept {
		if (!this->m_is_valid)
			return;

		// dont throw
		try {
			CloseHandle(this->m_handle);
		} catch (...) {}

		this->m_is_valid = false;
	}

	// IRP_MJ_WRITE
	uint32_t Driver::write(const void* const buffer, const uint32_t size) const {
		DWORD num_bytes_written{ 0 };
		if (!WriteFile(this->m_handle, buffer, size, &num_bytes_written, nullptr))
			throw FailedToWriteFile{ mango_format_w32status(GetLastError()) };
		return num_bytes_written;
	}

	// IRP_MJ_READ
	uint32_t Driver::read(void* const buffer, const uint32_t size) const {
		DWORD num_bytes_read{ 0 };
		if (!ReadFile(this->m_handle, buffer, size, &num_bytes_read, nullptr))
			throw FailedToReadFile{ mango_format_w32status(GetLastError()) };
		return num_bytes_read;
	}

	// IRP_MJ_DEVICE_CONTROL
	uint32_t Driver::iocontrol(const uint32_t control_code, void* const in_buffer, 
		const uint32_t in_buffer_size, void* const out_buffer, const uint32_t out_buffer_size) const {
		DWORD bytes_returned{ 0 };
		if (!DeviceIoControl(this->m_handle, control_code, in_buffer, in_buffer_size, out_buffer, out_buffer_size, &bytes_returned, nullptr))
			throw IoControlFailed{ mango_format_w32status(GetLastError()) };
		return bytes_returned;
	}

	// register and start a service using the service control manager
	SC_HANDLE create_and_start_service(const std::string_view service_name, const std::string_view file_path) {
		const auto sc_manager{ OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE) };
		if (!sc_manager)
			throw FailedToOpenServiceControlManager{ mango_format_w32status(GetLastError()) };

		// close the service control manager handle
		const ScopeGuard _guardone{ &CloseServiceHandle, sc_manager };

		const std::string null_terminated_name(service_name),
			null_terminated_path(file_path);

		// create our service
		const auto service{ CreateServiceA(
			sc_manager,
			null_terminated_name.c_str(),
			null_terminated_name.c_str(),
			SERVICE_START | SERVICE_STOP | DELETE,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_IGNORE,
			null_terminated_path.c_str(),
			nullptr,
			nullptr,
			nullptr,
			nullptr,
			nullptr
		) };
		if (!service)
			throw FailedToCreateService{ mango_format_w32status(GetLastError()) };

		// if StartService fails, delete the service and close the handle
		ScopeGuard _guardtwo{ &CloseServiceHandle, service },
			_guardthree{ &DeleteService, service };

		// start the service
		if (!StartServiceA(service, 0, nullptr))
			throw FailedToStartService{ mango_format_w32status(GetLastError()) };

		// no errors, cool
		_guardtwo.cancel(_guardthree);
		return service;
	}

	// stop and remove a running service
	void stop_and_delete_service(const SC_HANDLE service) {
		// if we throw an exception, do not leak the handle
		const ScopeGuard _guard{ &CloseServiceHandle, service };

		// stop the service
		SERVICE_STATUS _unused{};
		if (!ControlService(service, SERVICE_CONTROL_STOP, &_unused))
			throw FailedToStopService{ mango_format_w32status(GetLastError()) };

		// delete the service
		if (!DeleteService(service))
			throw FailedToDeleteService{ mango_format_w32status(GetLastError()) };
	}
} // namespace mango