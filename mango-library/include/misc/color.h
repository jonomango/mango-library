#pragma once

#include "vector.h"

// fkn windows
#undef max
#undef min


namespace mango {
	// floating-point types are in the range of [0, 1]
	// integral types are in the range of [0, std::numeric_limits<T>::max()]
	template <typename T>
	class ColorRGBA : public Vector<T, 4> {
	public:
		constexpr explicit ColorRGBA(const T& scalar = T(0)) : ColorRGBA(scalar, scalar, scalar) {}
		constexpr ColorRGBA(const T& r, const T& g, const T& b, const T& a)
			: Vector<T, 4>(r, g, b, a) {}

		// kinda poop but i couldn't think of a better way to implement this without using 2 contructors
		constexpr ColorRGBA(const T& r, const T& g, const T& b)
			: Vector<T, 4>(r, g, b, T(0)) {
			if constexpr (std::is_floating_point<T>::value)
				this->alpha(T(1));
			else
				this->alpha(T(std::numeric_limits<T>::max()));
		}

		// get and set the red component
		const T& red() const { return this->at(0); }
		void red(const T& value) { this->at(0) = value; }

		// get and set the green component
		const T& green() const { return this->at(1); }
		void green(const T& value) { this->at(1) = value; }

		// get and set the blue component
		const T& blue() const { return this->at(2); }
		void blue(const T& value) { this->at(2) = value; }

		// get and set the alpha component
		const T& alpha() const { return this->at(3); }
		void alpha(const T& value) { this->at(3) = value; }

	private:
	};

	// hue, saturation, brightness - all in the range of [0, 1]
	template <typename T>
	class ColorHSBA : public Vector<T, 4> {
	public:
		constexpr ColorHSBA() : ColorHSBA(T(0), T(0), T(0)) {}
		constexpr ColorHSBA(const T& h, const T& s, const T& b, const T& a = T(1)) 
			: Vector<T, 4>(h, s, b, a) {}

		// get and set the hue component
		const T& hue() const { return this->at(0); }
		void hue(const T& value) { this->at(0) = value; }

		// get and set the saturation component
		const T& saturation() const { return this->at(1); }
		void saturation(const T& value) { this->at(1) = value; }

		// get and set the brightness component
		const T& brightness() const { return this->at(2); }
		void brightness(const T& value) { this->at(2) = value; }

		// get and set the alpha component
		const T& alpha() const { return this->at(3); }
		void alpha(const T& value) { this->at(3) = value; }

	private:
		// only floats
		static_assert(std::is_floating_point<T>::value, "Only floating-point types allowed");
	};

	// doesn't follow the naming scheme but whatever
	using rgba8 = ColorRGBA<uint8_t>;
	using rgba16 = ColorRGBA<uint16_t>;
	using rgba32 = ColorRGBA<uint32_t>;

	using rgbaf = ColorRGBA<float>;
	using rgbad = ColorRGBA<double>;

	using hsbaf = ColorHSBA<float>;
	using hsbad = ColorHSBA<double>;
} // namespace mango