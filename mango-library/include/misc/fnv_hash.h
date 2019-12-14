#pragma once

#include <array>

#include "../misc/misc.h"


namespace mango {
	// fnv1 offset
	template <typename T> constexpr T fnv1_offset();
	template <> constexpr uint32_t fnv1_offset() { return 2166136261ui32; }
	template <> constexpr uint64_t fnv1_offset() { return 14695981039346656037ui64; }

	// fnv1 prime
	template <typename T> constexpr T fnv1_prime();
	template <> constexpr uint32_t fnv1_prime() { return 16777619ui32; }
	template <> constexpr uint64_t fnv1_prime() { return 1099511628211ui64; }

	// compile-time FNV-1 class
	template <typename T>
	class Fnv1 {
	public:
		constexpr Fnv1() noexcept = default;
		constexpr Fnv1(const T hash) noexcept : m_value(hash) {}

		// construct from a string
		template <size_t Size>
		constexpr Fnv1(const char(&str)[Size]) noexcept
			: m_value(this->construct_hash(str)) {}
		constexpr Fnv1(const StringWrapper str) noexcept
			: m_value(this->construct_hash(str)) {}

		// get the hash
		constexpr operator T() const noexcept { return this->m_value; }
		constexpr T operator()() const noexcept { return this->m_value; }

	private:
		// make the hash
		static constexpr T construct_hash(const StringWrapper str) {
			auto hash = fnv1_offset<T>();
			for (size_t i = 0; i < str.get_size(); ++i)
				hash = (hash * fnv1_prime<T>()) ^ str.get_str()[i];
			return hash;
		}

	private:
		const T m_value;
	};

	// compile-time FNV-1a class
	template <typename T>
	class Fnv1a {
	public:
		constexpr Fnv1a() noexcept = default;
		constexpr Fnv1a(const T hash) noexcept : m_value(hash) {}

		// construct from a string
		template <size_t Size>
		constexpr Fnv1a(const char(&str)[Size]) noexcept 
			: m_value(this->construct_hash(str)) {}
		constexpr Fnv1a(const StringWrapper str) noexcept
			: m_value(this->construct_hash(str)) {}

		// get the hash
		constexpr operator T() const noexcept { return this->m_value; }
		constexpr T operator()() const noexcept { return this->m_value; }

	private:
		// make the hash
		static constexpr T construct_hash(const StringWrapper str) {
			auto hash = fnv1_offset<T>();
			for (size_t i = 0; i < str.get_size(); ++i)
				hash = (hash ^ str.get_str()[i]) * fnv1_prime<T>();
			return hash;
		}

	private:
		const T m_value;
	};
} // namespace mango