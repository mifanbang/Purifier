/*
 *  purifier - removing ad banners in Microsoft Skype
 *  Copyright (C) 2011-2014 Mifan Bang <http://debug.tw>.
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


#define SK_MODULE_NAME		L"skype.exe"
#define SK_AD_WINDOW_NAME	L"TChatBanner"
#define SK_OS_ERROR_MSG		L"A call to an OS function failed."
#define SK_CLASS_ERROR_MSG	L"1411"  // error code for ERROR_CLASS_DOES_NOT_EXIST


#define APP_NAME		L"Purifier"
#define APP_VERSION		L"3.0.0"


#define FILE_LAUNCHER	L"launcher.exe"
#define FILE_PAYLOAD	L"payload.dll"


// We will pack the payload DLL into .text section of launcher program.
// Since common PE files have many 0x00 bytes, we will XOR them with
// fake NOP instructions (byte 0x90) to make the payload look more like
// normal code.
#define BYTE_OBFUSCATOR	0x90

