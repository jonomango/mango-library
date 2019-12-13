#pragma once

#include "process.h"


namespace mango {
	// this has a slight memory overhead, especially noticeable with several smaller datatypes
	// NOTE: obviously the lifetime of the process passed to the constructor should not end 
	// while still using the RWVariable, doing so is a user-error
	template <typename T>
	class RWVariable {
	public:
		RWVariable() = default;
		constexpr RWVariable(const Process& process, void* const address) noexcept { this->setup(process, uintptr_t(address)); }
		constexpr RWVariable(const Process& process, const uintptr_t address) noexcept { this->setup(process, address); }

		// copying
		constexpr RWVariable(const RWVariable& other) noexcept { *this = other; }
		constexpr RWVariable<T>& operator=(const RWVariable& other) noexcept {
			this->m_process = other.m_process;
			this->m_address = other.m_address;
			return *this;
		}

		// setup stuffz
		constexpr void setup(const Process& process, const uintptr_t address) noexcept {
			this->setup(process, reinterpret_cast<T*>(address)); 
		}
		constexpr void setup(const Process& process, void* const address) noexcept {
			this->m_address = reinterpret_cast<T* const>(address);
			this->m_process = &process;
		}

		// this is pretty dangerous but fuck you
		// you can still use std::addressof to get the true address
		constexpr T* operator&() const noexcept {
			return this->m_address;
		}

		// for arrays
		RWVariable<T> operator[](const size_t index) const {
			return RWVariable<T>(*this->m_process, this->m_address + index);
		}

		// read
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