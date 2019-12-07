#pragma once

#include "vector.h"


namespace mango {
	template <typename T, size_t Rows, size_t Columns>
	class Matrix : public std::array<Vector<T, Columns>, Rows> {
	public:

	private:
	};

	using Matrix2x2f = Matrix<float, 2, 2>;
	using Matrix3x2f = Matrix<float, 3, 2>;
	using Matrix4x2f = Matrix<float, 4, 2>;

	using Matrix2x3f = Matrix<float, 2, 3>;
	using Matrix3x3f = Matrix<float, 3, 3>;
	using Matrix4x3f = Matrix<float, 4, 3>;

	using Matrix2x4f = Matrix<float, 2, 4>;
	using Matrix3x4f = Matrix<float, 3, 4>;
	using Matrix4x4f = Matrix<float, 4, 4>;
} // namespace mango