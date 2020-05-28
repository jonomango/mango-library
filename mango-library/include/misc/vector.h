#pragma once

#include <array>
#include <ostream>
#include <iomanip>
#include <numeric>

#include "misc.h"

// fkn windows
#undef min
#undef max


namespace mango {
	// vector class for math stuffz
	template <typename T, size_t C>
	class Vector : public std::array<T, C> {
	public:
		// only arithmetic values
		static_assert(std::is_arithmetic_v<T>, "Only arithmetic types supported");

		// dimension >= 1
		static_assert(C >= 1, "Must have a size of one or more");

		// std::array::fill() is not constexpr btw
		constexpr explicit Vector(const T& scalar = T{ 0 }) noexcept {
			for_constexpr<0, C, 1>([&](const size_t i) {
				(*this)[i] = scalar;
			});
		}

		// copy constructor
		template <typename Type>
		constexpr explicit Vector(const Vector<Type, C>& other) noexcept {
			for_constexpr<0, C, 1>([&](const size_t i) {
				(*this)[i] = T(other[i]);
			});
		}

		// copy constructor from std::array
		template <typename Type>
		constexpr explicit Vector(const std::array<Type, C>& other) noexcept {
			for_constexpr<0, C, 1>([&](const size_t i) {
				(*this)[i] = T(other[i]);
			});
		}

		// Vector(...) or Vector({...}) or Vector v = {...}
		template <typename... Args>
		constexpr Vector(const Args&... args) noexcept : std::array<T, C>{ T(args)... } {
			static_assert(sizeof...(Args) == C, "Incorrect amount of arguments provided");
		}

		// addition
		constexpr Vector<T, C>& operator+=(const Vector<T, C>& other) {
			return *this = (*this + other);
		}
		constexpr Vector<T, C> operator+(const Vector<T, C>& other) const {
			Vector<T, C> copy{ *this };
			for_constexpr<0, C, 1>([&](const size_t i) {
				copy[i] += other[i];
			});
			return copy;
		}

		// subtraction
		constexpr Vector<T, C>& operator-=(const Vector<T, C>& other) {
			return *this = (*this - other);
		}
		constexpr Vector<T, C> operator-(const Vector<T, C>& other) const {
			Vector<T, C> copy{ *this };
			for_constexpr<0, C, 1>([&](const size_t i) {
				copy[i] -= other[i];
			});
			return copy;
		}

		// multiplication
		constexpr Vector<T, C>& operator*=(const Vector<T, C>& other) {
			return *this = (*this * other);
		}
		constexpr Vector<T, C> operator*(const Vector<T, C>& other) const {
			Vector<T, C> copy{ *this };
			for_constexpr<0, C, 1>([&](const size_t i) {
				copy[i] *= other[i];
			});
			return copy;
		}

		// division
		constexpr Vector<T, C>& operator/=(const Vector<T, C>& other) {
			return *this = (*this / other);
		}
		constexpr Vector<T, C> operator/(const Vector<T, C>& other) const {
			Vector<T, C> copy{ *this };
			for_constexpr<0, C, 1>([&](const size_t i) {
				copy[i] /= other[i];
			});
			return copy;
		}

		// get the length (or magnitude) of a vector
		template <const size_t D = C>
		T length() const noexcept {
			// D must be in the range of (0, C]
			static_assert(D <= C, "D cannot be higher than C");
			static_assert(D >= 1, "D must be one or greater");

			T total{ 0 };
			for (size_t i = 0; i < D; ++i)
				total += (*this)[i] * (*this)[i];

			return total <= T(0) ? T(0) : std::sqrt(total);
		}

		// normalize a vector (in place)
		const Vector<T, C>& normalize() noexcept {
			// only floats
			static_assert(std::is_floating_point_v<T>, "Only floating-point vectors can be normalized");

			const auto length{ this->length() };

			// can't divide by 0
			if (length <= 0.0)
				return *this;

			for (auto& x : *this)
				x /= T(length);

			return *this;
		}

		// return a normalized vector
		static Vector<T, C> normalize(Vector<T, C> vec) noexcept {
			vec.normalize();
			return vec;
		}

		// the sum of all elements
		constexpr T sum() const noexcept {
			T total = 0;
			for (const auto x : *this)
				total += x;
			return total;
		}

		// find the mean
		constexpr T mean() const noexcept {
			return this->sum() / T(C);
		}

		// find the median
		constexpr T median() const noexcept {
			const auto center = C / 2 - 1;
			if (C % 2 == 0) { // even
				return ((*this)[center] + (*this)[center + 1]) / T(2);
			} else { // odd
				return (*this)[center];
			}
		}

		// dot-product
		constexpr T dot(const Vector<T, C>& other) const noexcept {
			T total = 0;
			for (size_t i = 0; i < C; ++i)
				total += (*this)[i] * other[i];
			return total;
		}
	};

	// lets you do stuff like std::cout << vec;
	template <typename T, const size_t C>
	std::ostream& operator<<(std::ostream& stream, const Vector<T, C>& vec) {
		stream << "[ " << +vec.front();
		for (size_t i{ 1 }; i < vec.size(); ++i)
			stream << ", " << +vec[i];
		return stream << " ]";
	}

	// lets you do stuff like std::wcout << vec;
	template <typename T, const size_t C>
	std::wostream& operator<<(std::wostream& stream, const Vector<T, C>& vec) {
		stream << L"[ " << +vec.front();
		for (size_t i{ 1 }; i < vec.size(); ++i)
			stream << L", " << +vec[i];
		return stream << L" ]";
	}

	// floats
	using Vec2f = Vector<float, 2>;
	using Vec3f = Vector<float, 3>;
	using Vec4f = Vector<float, 4>;

	// doubles
	using Vec2d = Vector<float, 2>;
	using Vec3d = Vector<float, 3>;
	using Vec4d = Vector<float, 4>;
		  
	// ints
	using Vec2i = Vector<int, 2>;
	using Vec3i = Vector<int, 3>;
	using Vec4i = Vector<int, 4>;
} // namespace mango