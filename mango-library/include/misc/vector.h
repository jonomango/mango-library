#pragma once

#include <array>
#include <ostream>
#include <iomanip>
#include <numeric>

// fkn windows
#undef min
#undef max


namespace mango {
	// vector class for math stuffz
	template <typename Ret, const size_t C>
	class Vector : public std::array<Ret, C> {
	public:
		constexpr Vector() = default;
		constexpr Vector(const Ret& value) { this->fill(value); }

		// Vector(...) or Vector({...}) or Vector v = {...}
		template <typename... Args>
		constexpr Vector(const Args&... args) : std::array<Ret, C>({ Ret(args)... }) {}

		// constexpr accumulate function
		template <typename Fn>
		constexpr Ret accumulate(const size_t start, const size_t end, const Ret initial, const Fn op) const {
			Ret value = initial;
			for (size_t i = start; i < end; ++i)
				value = op(value, this->at(i));
			return value;
		}

		// default op is std::plus
		constexpr Ret accumulate(const size_t start, const size_t end, const Ret initial) const {
			return this->accumulate(start, end, initial, std::plus<Ret>());
		}

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

			const auto total = this->accumulate(0, D, 0.0, square);
			if (!total)
				return 0.0;

			return std::sqrt(total);
		}

		// normalize a vector (in place)
		void normalize() {
			// only floats
			static_assert(std::is_floating_point<Ret>::value, "Only floating-point vectors can be normalized");

			const auto length = this->length();

			// can't divide by 0
			if (!length)
				return;

			const auto divide = [=](const Ret x) {
				return Ret(x / length);
			};

			// divide all elements by length
			std::transform(this->begin(), this->end(), this->begin(), divide);
		}

		// find the mean (obviously)
		constexpr double mean() const {
			return this->accumulate(0, this->size(), 0.0) / double(C);
		}

		// find the median (obviously)
		// also it returns double instead of T due to cases where C is even
		constexpr double median() const {
			const auto center = C / 2 - 1;
			if (C % 2 == 0) // even
				return (double(this->at(center)) + double(this->at(center + 1))) / 2.0;
			else // odd
				return double(this->at(center));
		}

	private:
		// only arithmetic values
		static_assert(std::is_arithmetic<Ret>::value, "Only arithmetic types supported");
	};

	// lets you do stuff like std::cout << vec;
	template <typename Ret, const size_t C>
	std::ostream& operator<<(std::ostream& stream, const Vector<Ret, C>& vec) {
		stream << "[ " << +vec.front();
		for (size_t i = 1; i < vec.size(); ++i)
			stream << ", " << +vec[i];
		stream << " ]";
		return stream;
	}

	// lets you do stuff like std::wcout << vec;
	template <typename Ret, const size_t C>
	std::wostream& operator<<(std::wostream& stream, const Vector<Ret, C>& vec) {
		stream << L"[ " << +vec.front();
		for (size_t i = 1; i < vec.size(); ++i)
			stream << L", " << +vec[i];
		stream << L" ]";
		return stream;
	}
} // namespace mango