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

#pragma once


constexpr wchar_t* c_appName = L"Purifier";
constexpr wchar_t* c_appVersion = L"3.3.1-pre";
constexpr wchar_t* c_evtBrowserHostSync = L"PurifiedSkypeBrowserHost";


// for resource file
#ifdef RC_INVOKED
	#define RES_APP_VER		"3.3.1-pre"
	#define RES_APP_VER_INT	3,3,0,-1
#endif  // RC_INVOKED


// We will pack the payload DLL into .text section of launcher program.
// Since common PE files have many 0x00 bytes, we will XOR them with
// fake NOP instructions (byte 0x90) to make the payload look more like
// normal code.
constexpr unsigned char c_byteObfuscator = 0x90;
