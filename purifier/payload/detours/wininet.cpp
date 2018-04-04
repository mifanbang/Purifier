/*
 *  purifier - removing ad banners in Microsoft Skype
 *  Copyright (C) 2011-2018 Mifan Bang <https://debug.tw>.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <array>

#include <shlwapi.h>

#include <gandr/hooking.h>

#include "shared/purifier.h"
#include "shared/util.h"
#include "wininet.h"


namespace detour {



static bool IsAdUrl(const wchar_t* url)
{
	std::array<const wchar_t*, 2> urlList = { {
		L"chatadwidget",
		L"adcontrol"
	} };

	return std::any_of(urlList.cbegin(), urlList.cend(), [url] (auto* keyword) -> bool {
		return StrStrIW(url, keyword) != nullptr;
	} );
}



HINTERNET WINAPI HttpOpenRequestW(
	_In_  HINTERNET hConnect,
	_In_  LPCWSTR lpszVerb,
	_In_  LPCWSTR lpszObjectName,
	_In_  LPCWSTR lpszVersion,
	_In_  LPCWSTR lpszReferer,
	_In_  LPCWSTR* lplpszAcceptTypes,
	_In_  DWORD dwFlags,
	_In_  DWORD_PTR dwContext
)
{
	DEBUG_MSG(L"HttpOpenRequestW: %s %s\n", lpszVerb, lpszObjectName);

	// checks for blockage
	if (IsAdUrl(lpszObjectName)) {
		SetLastError(ERROR_INTERNET_INVALID_URL);  // fakes an error
		return nullptr;
	}

	return CallTram32(::HttpOpenRequestW)(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
}



}  // detour
