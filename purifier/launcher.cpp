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

#include <algorithm>
#include <string>

#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>

#include "purifier.h"
#include "util.h"
#include "payload.h"



// output localized error message if $dwErrCode is non-zero
static void ErrorMessageBox(LPCWSTR lpszMsg, DWORD dwErrCode)
{
	LPWSTR buffer;

	if (dwErrCode) {
		LPWSTR lpszErrMsg;
		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			dwErrCode,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(wchar_t*)&lpszErrMsg,
			0,
			NULL
		);

		buffer = new WCHAR[wcslen(lpszErrMsg) + wcslen(lpszMsg) + 128];
		wsprintf(buffer, L"An error occurred during launching.\n\nFunction: %s\nCode: %d\nDetail: %s", lpszMsg, dwErrCode, lpszErrMsg);
		LocalFree(lpszErrMsg);
	}
	else {
		buffer = new WCHAR[wcslen(lpszMsg) + 128];
		wsprintf(buffer, L"An error occurred during launching.\n\nDetail: %s", lpszMsg);
	}
	MessageBox(NULL, buffer, APP_NAME, MB_OK | MB_ICONERROR);

	delete[] buffer;
}



// return true on success; return false otherwise
static bool UnpackPayloadTo(const std::wstring& path)
{
	auto lpszPath = path.c_str();
	bool bShouldUnpack = true;
	bool bSucceeded = false;

	// check for path
	bShouldUnpack = bShouldUnpack && !PathFileExists(lpszPath);

	// match the hash of payload with that of an pre-existing file
	bShouldUnpack = bShouldUnpack || !CheckFileHash(lpszPath, s_payloadHash);

	if (bShouldUnpack) {
		DWORD dwPayloadSize = sizeof(s_payloadData);
		LPBYTE lpPayloadData = new BYTE[dwPayloadSize];
		memcpy(lpPayloadData, s_payloadData, dwPayloadSize);

		// de-obfuscate our code
		for (DWORD i = 0; i < dwPayloadSize; i++)
			lpPayloadData[i] ^= BYTE_OBFUSCATOR;

		// write to a temp path
		HANDLE hFile;
		DWORD dwWritten;
		hFile = CreateFile(lpszPath, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			WriteFile(hFile, lpPayloadData, dwPayloadSize, &dwWritten, nullptr);
			CloseHandle(hFile);
			bSucceeded = true;
		}

		delete[] lpPayloadData;
	}
	else
		bSucceeded = true;  // file already exists

	return bSucceeded;
}



int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int)
{
	DebugConsole dbgConsole;

	// generate DLL path in user's Temp directory
	auto pathPayload = GetPayloadPath();
	DEBUG_MSG(L"Payload path: %s\n", pathPayload.c_str());
	if (!UnpackPayloadTo(pathPayload)) {
		ErrorMessageBox(L"UnpackPayloadTo()", GetLastError());
		return 0;
	}

	// get executable paths
	auto pathSkypeExe = GetSkypePath();
	if (pathSkypeExe.empty()) {
		ErrorMessageBox(L"Failed to locate install directory from registry", NULL);
		return 0;  // according to MSDN, we should return zero before entering the message loop
	}
	DEBUG_MSG(L"Skype path: %s\n", pathSkypeExe.c_str());

	// create and purify SkypeBrowserHost.exe
	auto pathBrowserHost = GetBrowserHostPath();
	if (!pathBrowserHost.empty())
		CreatePurifiedProcess(pathBrowserHost.c_str(), L"-Embedding", pathPayload.c_str());

	// create and purify skype.exe
	auto retCreateProc = CreatePurifiedProcess(pathSkypeExe.c_str(), nullptr, pathPayload.c_str());
	if (retCreateProc != NO_ERROR) {
		ErrorMessageBox(L"CreatePurifiedProcess()", retCreateProc);
		return retCreateProc;
	}

	return NO_ERROR;
}

