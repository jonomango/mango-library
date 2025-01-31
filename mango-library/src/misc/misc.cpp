#include "../../include/misc/misc.h"

#include <locale>
#include <codecvt>


namespace mango {
	using WCharConverter = std::codecvt_utf8<wchar_t>;

	// wstring to string conversions
	std::string wstr_to_str(const std::wstring_view str) {
		std::wstring_convert<WCharConverter, wchar_t> converter;
		return converter.to_bytes(str.data(), str.data() + str.size());
	}
} // namespace mango