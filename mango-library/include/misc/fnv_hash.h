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

	// compile time FNV-1 function
	template <typename T>
	constexpr T fnv1(const StringWrapper& str) {
		auto hash = fnv1_offset<T>();
		for (size_t i = 0; i < str.get_size(); ++i)
			hash = (hash * fnv1_prime<T>()) ^ str.get_str()[i];
		return hash;
	}

	// compile time FNV-1a function (recommended over FNV-1)
	template <typename T>
	constexpr T fnv1a(const StringWrapper& str) {
		auto hash = fnv1_offset<T>();
		for (size_t i = 0; i < str.get_size(); ++i)
			hash = (hash ^ str.get_str()[i]) * fnv1_prime<T>();
		return hash;
	}
} // namespace mango