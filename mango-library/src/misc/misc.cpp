#include "../../include/misc/misc.h"

#include <locale>
#include <codecvt>


namespace mango {
	using WCharConverter = std::codecvt_utf8<wchar_t>;

	// std::wstring and std::string conversions
	std::wstring str_to_wstr(const std::string& str) {
		std::wstring_convert<WCharConverter, wchar_t> converter;
		return converter.from_bytes(str);
	}
	std::string wstr_to_str(const std::wstring& str) {
		std::wstring_convert<WCharConverter, wchar_t> converter;
		return converter.to_bytes(str);
	}
} // namespace mango