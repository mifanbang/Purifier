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

#pragma once

#include <windows.h>
#include <wininet.h>


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
);



}  // namespace detour
