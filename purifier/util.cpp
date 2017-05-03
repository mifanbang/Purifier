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

#include <functional>

#include <windows.h>
#include <wincrypt.h>

#include <gandr/Debugger.h>

#include "DllPreloadDebugSession.h"
#include "purifier.h"
#include "util.h"



// ---------------------------------------------------------------------------
// debug utilities
// ---------------------------------------------------------------------------

DebugConsole::DebugConsole()
{
#ifdef _DEBUG
	FILE* fp;
	AllocConsole();
	freopen_s(&fp, "CONIN$", "r+t", stdin);
	freopen_s(&fp, "CONOUT$", "w+t", stdout);
	freopen_s(&fp, "CONOUT$", "w+t", stderr);
#endif  // _DEBUG
}


DebugConsole::~DebugConsole()
{
#ifdef _DEBUG
	DEBUG_MSG(L"I'm done\n");
	system("pause");

	FreeConsole();
#endif  // _DEBUG
}


// ---------------------------------------------------------------------------
// hash functions
// ---------------------------------------------------------------------------

WinErrorCode ReadFileToBuffer(const wchar_t* lpPath, unsigned char** lpOutPtr, unsigned int* lpOutBufferSize)
{
	DWORD dwLastError = NO_ERROR;

	HANDLE hFile;
	hFile = CreateFile(lpPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, nullptr);
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD dummy;
		DWORD dwSizePayload;
		LPBYTE lpDataPayload;

		dwSizePayload = GetFileSize(hFile, nullptr);
		lpDataPayload = new BYTE[dwSizePayload];
		if (ReadFile(hFile, lpDataPayload, dwSizePayload, &dummy, nullptr) == TRUE) {
			*lpOutPtr = lpDataPayload;
			*lpOutBufferSize = dwSizePayload;
		}
		else
			dwLastError = GetLastError();

		CloseHandle(hFile);
	}
	else
		dwLastError = GetLastError();

	return dwLastError;
}


WinErrorCode GenerateMD5Hash(const unsigned char* lpData, unsigned int uiDataSize, Hash128* lpOutHash)
{
	DWORD dwLastError = NO_ERROR;

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	unsigned char cbHash[16];
	DWORD dwHashSize = sizeof(cbHash);

	bool isSuccessful = true;
	isSuccessful = isSuccessful && CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) != FALSE;
	isSuccessful = isSuccessful && CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash) != FALSE;
	isSuccessful = isSuccessful && CryptHashData(hHash, lpData, uiDataSize, 0) != FALSE;
	isSuccessful = isSuccessful && CryptGetHashParam(hHash, HP_HASHVAL, cbHash, &dwHashSize, 0) != FALSE;
	if (isSuccessful)
		CopyMemory(lpOutHash->cbData, cbHash, sizeof(cbHash));
	else
		dwLastError = GetLastError();

	if (hHash != 0)
		CryptDestroyHash(hHash);
	if (hProv != 0)
		CryptReleaseContext(hProv, 0);

	return dwLastError;
}


bool CheckFileHash(const wchar_t* lpszPath, const Hash128& hash)
{
	unsigned int dwSizeFileOnDisk = 0;
	unsigned char* lpDataFileOnDisk = nullptr;
	Hash128 hashFileOnDisk;

	bool bDoHashesMatch = true;
	bDoHashesMatch = bDoHashesMatch && ReadFileToBuffer(lpszPath, &lpDataFileOnDisk, &dwSizeFileOnDisk) == NO_ERROR;
	bDoHashesMatch = bDoHashesMatch && GenerateMD5Hash(lpDataFileOnDisk, dwSizeFileOnDisk, &hashFileOnDisk) == NO_ERROR;
	bDoHashesMatch = bDoHashesMatch && memcmp(hashFileOnDisk.cbData, hash.cbData, sizeof(hash.cbData)) == 0;

	if (lpDataFileOnDisk != nullptr)
		delete[] lpDataFileOnDisk;

	return bDoHashesMatch;
}


// ---------------------------------------------------------------------------
// process creation function
// ---------------------------------------------------------------------------

WinErrorCode CreatePurifiedProcess(const wchar_t* szExePath, const wchar_t* szArg, const wchar_t* szPayloadPath)
{
	gan::Debugger debugger;

	gan::DebugSession::CreateProcessParam createParam;
	createParam.imagePath = szExePath;
	createParam.args = szArg;
	if (!debugger.AddSession<DLLPreloadDebugSession>(createParam, szPayloadPath))
		return GetLastError();

	if (debugger.EnterEventLoop() == gan::Debugger::EventLoopResult::ErrorOccurred)
		return GetLastError();

	return NO_ERROR;
}


// ---------------------------------------------------------------------------
// path functions
// ---------------------------------------------------------------------------

std::wstring GetPayloadPath()
{
	WCHAR buffer[MAX_PATH];
	GetTempPath(sizeof(buffer) / sizeof(buffer[0]), buffer);
	wcsncat_s(buffer, sizeof(buffer) / sizeof(buffer[0]), APP_NAME L"-" APP_VERSION L".dll", _TRUNCATE);

	return std::wstring(buffer);
}


std::wstring GetSkypePath()
{
	std::wstring pathSkypeExe;

	HKEY hRegKey;
	DWORD dwSize = MAX_PATH;
	wchar_t szPath[MAX_PATH];

	if (RegOpenKey(HKEY_CURRENT_USER, L"SOFTWARE\\Skype\\Phone", &hRegKey) == NO_ERROR) {
		if (RegQueryValueEx(hRegKey, L"SkypePath", nullptr, nullptr, reinterpret_cast<PBYTE>(szPath), &dwSize) == NO_ERROR)
			pathSkypeExe = szPath;
		RegCloseKey(hRegKey);
	}

	return pathSkypeExe;
}


std::wstring GetBrowserHostPath()
{
	std::wstring pathBrowserHostExe;

	HKEY hRegKey;
	DWORD dwSize = MAX_PATH;
	wchar_t szPath[MAX_PATH];

	if (RegOpenKey(HKEY_CLASSES_ROOT, L"CLSID\\{3FCB7074-EC9E-4AAF-9BE3-C0E356942366}\\LocalServer32", &hRegKey) == NO_ERROR) {
		if (RegQueryValueEx(hRegKey, nullptr, nullptr, nullptr, reinterpret_cast<PBYTE>(szPath), &dwSize) == NO_ERROR) {
			if (szPath[0] == '"')
				pathBrowserHostExe = szPath + 1;
			else
				pathBrowserHostExe = szPath;

			if (pathBrowserHostExe.back() == '\"')
				pathBrowserHostExe.pop_back();
		}
		RegCloseKey(hRegKey);
	}

	return pathBrowserHostExe;
}
