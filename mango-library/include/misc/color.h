#pragma once

#include "vector.h"


namespace mango {
	// floating-point types are in the range of [0, 1]
	// integral types are in the range of [0, std::numeric_limits<T>::max()]
	template <typename Ret>
	class ColorRGBA : public Vector<Ret, 4> {
	public:
		constexpr ColorRGBA() : ColorRGBA(Ret(0), Ret(0), Ret(0)) { }
		constexpr ColorRGBA(const Ret& r, const Ret& g, const Ret& b, const Ret& a)
			: Vector<Ret, 4>(r, g, b, a) {}

		// kinda poop but i couldn't think of a better way to implement this without using 2 contructors
		constexpr ColorRGBA(const Ret& r, const Ret& g, const Ret& b)
			: Vector<Ret, 4>(r, g, b) {
			if constexpr (std::is_floating_point<Ret>::value)
				this->alpha(Ret(1));
			else
				this->alpha(Ret(std::numeric_limits<Ret>::max()));
		}

		// get and set the red component
		const Ret& red() const { return this->at(0); }
		void red(const Ret& value) { this->at(0) = value; }

		// get and set the green component
		const Ret& green() const { return this->at(1); }
		void green(const Ret& value) { this->at(1) = value; }

		// get and set the blue component
		const Ret& blue() const { return this->at(2); }
		void blue(const Ret& value) { this->at(2) = value; }

		// get and set the alpha component
		const Ret& alpha() const { return this->at(3); }
		void alpha(const Ret& value) { this->at(3) = value; }

	private:
	};

	// hue, saturation, brightness - all in the range of [0, 1]
	template <typename Ret>
	class ColorHSBA : public Vector<Ret, 4> {
	public:
		constexpr ColorHSBA() : ColorHSBA(Ret(0), Ret(0), Ret(0)) {}
		constexpr ColorHSBA(const Ret& h, const Ret& s, const Ret& b, const Ret& a = Ret(1)) 
			: Vector<Ret, 4>(h, s, b, a) {}

		// get and set the hue component
		const Ret& hue() const { return this->at(0); }
		void hue(const Ret& value) { this->at(0) = value; }

		// get and set the saturation component
		const Ret& saturation() const { return this->at(1); }
		void saturation(const Ret& value) { this->at(1) = value; }

		// get and set the brightness component
		const Ret& brightness() const { return this->at(2); }
		void brightness(const Ret& value) { this->at(2) = value; }

		// get and set the alpha component
		const Ret& alpha() const { return this->at(3); }
		void alpha(const Ret& value) { this->at(3) = value; }

	private:
		// only floats
		static_assert(std::is_floating_point<Ret>::value, "Only floating-point types allowed");
	};
} // namespace mango