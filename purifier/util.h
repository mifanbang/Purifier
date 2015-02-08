/*
 *  purifier - removing ad banners in Microsoft Skype
 *  Copyright (C) 2011-2015 Mifan Bang <http://debug.tw>.
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


// ---------------------------------------------------------------------------
// data type definitions
// ---------------------------------------------------------------------------

typedef unsigned int	WinErrorCode;  // equivalent to DWORD

struct Hash128 {
	unsigned char cbData[16];
};


// ---------------------------------------------------------------------------
// functions
// ---------------------------------------------------------------------------

// allocates a buffer with sufficient size and loads the content of a file into it
// NOTE: The memory is allocated via operator new[], so the caller must later use delete[] to release buffer
// @param lpPath - path to the file
// @param lpOutPtr - address of the pointer to the buffer
// @param lpOutBufferSize - size of the buffer
// @return a Windows error code indicating the result of the last internal system call
WinErrorCode ReadFileToBuffer(const wchar_t* lpPath, unsigned char** lpOutPtr, unsigned int* lpOutBufferSize);

// generate the MD5 hash for a given buffer
// @param lpData - pointer to the data
// @param uiDataSize - size of the data
// @param lpOutHash - pointer to the result hash
// @return a Windows error code indicating the result of the last internal system call
WinErrorCode GenerateMD5Hash(const unsigned char* lpData, unsigned int uiDataSize, Hash128* lpOutHash);
