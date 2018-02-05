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

#include <string>
#include <memory>
#include <utility>

#include <gandr/Buffer.h>



// ---------------------------------------------------------------------------
// data type definitions
// ---------------------------------------------------------------------------

using WinErrorCode = std::uint32_t;  // equivalent to DWORD

struct Hash128
{
	std::uint8_t cbData[16];
};


// ---------------------------------------------------------------------------
// debug utilities
// ---------------------------------------------------------------------------

#ifdef _DEBUG
#include <stdio.h>
#define DEBUG_MSG	wprintf
#else
#define DEBUG_MSG
#endif  // _DEBUG


class DebugConsole
{
public:
	DebugConsole();
	~DebugConsole();
};


// ---------------------------------------------------------------------------
// functions
// ---------------------------------------------------------------------------

// allocate a buffer with sufficient size and loads the content of a file into it
// @return a Windows error code indicating the result of the last internal system call
std::unique_ptr<gan::Buffer> ReadFileToBuffer(const wchar_t* lpPath, WinErrorCode& errCode);

// generate the MD5 hash for a given buffer
// @param lpData - pointer to the data
// @param uiDataSize - size of the data
// @param lpOutHash - pointer to the result hash
// @return a Windows error code indicating the result of the last internal system call
WinErrorCode GenerateMD5Hash(const unsigned char* lpData, unsigned int uiDataSize, Hash128* lpOutHash);

// check if a file has a certain hash
bool CheckFileHash(const wchar_t* lpszPath, const Hash128& hash);


// create and purify a new process before running entry point
// @return pid of the new process
uint32_t CreatePurifiedProcess(const wchar_t* szExePath, const wchar_t* szArg, const wchar_t* szPayloadPath);


// obtain the path of payload DLL
std::wstring GetPayloadPath();

// obtain the path to the installed Skype.exe
// @return empty string if failed
std::wstring GetSkypePath();

// obtain the path to the installed SkypeBrowserHost.exe
// @return empty string if failed
std::wstring GetBrowserHostPath();

// obtain the name of event to sync between SkypeBrowserHost.exe and Skype.exe
std::wstring GetBrowserHostEventName(uint32_t pid);
