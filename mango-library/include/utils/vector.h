#pragma once

#include <array>
#include <ostream>
#include <iomanip>
#include <numeric>


namespace mango {
	// vector class for arithmetic values
	template <typename T, const size_t C>
	class Vector : public std::array<T, C> {
	public:
		constexpr Vector() : std::array<T, C>() {}

		// Vector(...) or Vector({...}) or Vector v = {...}
		template <typename ...Args>
		constexpr Vector(const Args... args) : std::array<T, C>({ args... }) {}

		// get the length (or magnitude) of a vector
		template <const size_t D = C>
		double length() const {
			// D must be in the range of (0, C]
			static_assert(D <= C, "D cannot be higher than C");
			static_assert(D > 0, "D must be greater than 0");

			// (x * x) + (y * y) + ...
			const auto square = [](const double acc, const double x) {
				return acc + x * x;
			};

			const auto total = std::accumulate(this->begin(), this->begin() + D, 0.0, square);
			if (!total)
				return 0.0;

			return std::sqrt(total);
		}

		// normalize a vector (in place)
		void normalize() {
			// only floats
			static_assert(std::is_floating_point<T>::value, "Only floating-point vectors can be normalized");

			const auto length = this->length();

			// can't divide by 0
			if (!length) {
				this->fill(T(0));
				return;
			}

			const auto divide = [length](const T x) {
				return T(x / length);
			};

			// divide all elements by length
			std::transform(this->begin(), this->end(), this->begin(), divide);
		}

	private:
		// only arithmetic values
		static_assert(std::is_arithmetic<T>::value, "Non-arithmetic types not supported");
	};

	// lets you do stuff like std::cout << vec;
	template <typename T, const size_t C>
	std::ostream& operator<<(std::ostream& stream, const Vector<T, C>& vec) {
		stream << "[ " << vec.front();
		for (size_t i = 1; i < vec.size(); ++i)
			stream << ", " << +vec[i];
		stream << " ]";
		return stream;
	}

	// lets you do stuff like std::wcout << vec;
	template <typename T, const size_t C>
	std::wostream& operator<<(std::wostream& stream, const Vector<T, C>& vec) {
		stream << L"[ " << vec.front();
		for (size_t i = 1; i < vec.size(); ++i)
			stream << L", " << +vec[i];
		stream << L" ]";
		return stream;
	}
} // namespace mango