#pragma once

#include "process.h"


namespace mango {
	// this has a slight memory overhead, especially noticeable with several smaller datatypes
	// NOTE: obviously the lifetime of the process passed to the constructor should not end 
	// while still using the ReadWriteVariable, doing so is a user-error
	template <typename T>
	class ReadWriteVariable {
	public:
		ReadWriteVariable() = default;
		constexpr ReadWriteVariable(const Process& process, T* const address) { this->setup(process, address); }
		constexpr ReadWriteVariable(const Process& process, const uintptr_t address) { this->setup(process, address); }

		// copying
		constexpr ReadWriteVariable(const ReadWriteVariable& other) { *this = other; }
		constexpr ReadWriteVariable<T>& operator=(const ReadWriteVariable& other) {
			this->m_process = other.m_process;
			this->m_address = other.m_address;
			return *this;
		}

		// setup stuffz
		constexpr void setup(const Process& process, const uintptr_t address) { 
			this->setup(process, reinterpret_cast<T*>(address)); 
		}
		constexpr void setup(const Process& process, T* const address) {
			this->m_process = &process;
			this->m_address = address;
		}

		// this is pretty dangerous but fuck you
		// you can still use std::addressof to get the true address
		constexpr T* operator&() const {
			return this->m_address;
		}

		// read
		operator T() const {
			return this->m_process->read<T>(this->m_address);
		}
		T operator()() const {
			return this->m_process->read<T>(this->m_address);
		}

		// write
		T operator=(const T& value) const {
			this->m_process->write<T>(this->m_address, value);
			return value;
		}

	private:
		const Process* m_process = nullptr;
		T* m_address = nullptr;
	};
} // namespace mango