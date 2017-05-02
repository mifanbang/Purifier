/*
 *  purifier - removing ad banners in Microsoft Skype
 *  Copyright (C) 2011-2017 Mifan Bang <https://debug.tw>.
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

#include <shlwapi.h>

#include <gandr/hooking.h>

#include "purifier.h"
#include "util.h"
#include "detours/wininet.h"


namespace detour {



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
	if (StrStrIW(lpszObjectName, SK_AD_HTTP_REQ_NAME) != NULL) {
		SetLastError(ERROR_INTERNET_INVALID_URL);  // fakes an error
		return NULL;
	}

	// calls the original function with the help of a trampoline
	DWORD dwResult = NULL;
	gan::CallTrampoline32(::HttpOpenRequestW, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
	__asm mov dwResult, eax

	return reinterpret_cast<HINTERNET>(dwResult);
}



}  // detour
