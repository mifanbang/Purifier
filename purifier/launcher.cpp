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

#include <algorithm>
#include <string>

#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>

#ifdef _DEBUG
	#include <stdio.h>
	#define DEBUG_MSG	wprintf
#else
	#define DEBUG_MSG
#endif  // _DEBUG

#include "purifier.h"
#include "util.h"
#include "payload.h"
#include "DllInjector.h"


// output localized error message if $dwErrCode is non-zero
void ErrorMessageBox(LPCWSTR lpszMsg, DWORD dwErrCode)
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


// return true on success; false otherwise.
bool GetTempFilePath(LPWSTR lpszBuffer, DWORD dwLength)
{
	WCHAR buffer[MAX_PATH];
	GetTempPath(sizeof(buffer) / sizeof(buffer[0]), buffer);
	wcsncat_s(buffer, sizeof(buffer) / sizeof(buffer[0]), APP_NAME L"-" APP_VERSION L".dll", _TRUNCATE);
	return wcsncpy_s(lpszBuffer, dwLength, buffer, _TRUNCATE) == 0;
}


// return true if path found in registry; return false otherwise
bool GetInstallPath(wchar_t* lpPath, DWORD length)
{
	HKEY hRegKey;
	DWORD dwSize = MAX_PATH;
	wchar_t szPath[MAX_PATH];

	if (RegOpenKey(HKEY_CURRENT_USER, L"SOFTWARE\\Skype\\Phone", &hRegKey) == NO_ERROR) {
		if (RegQueryValueEx(hRegKey, L"SkypePath", NULL, NULL, (PBYTE)szPath, &dwSize) == NO_ERROR) {
			wcsncpy_s(lpPath, length, szPath, MAX_PATH);
			lpPath[length - 1] = NULL;
			RegCloseKey(hRegKey);
			return true;
		}
		RegCloseKey(hRegKey);
	}

	return false;
}


// check if a file has a certain hash
bool CheckFileHash(LPCWSTR lpszPath, const Hash128& hash)
{
	unsigned int dwSizeFileOnDisk = 0;
	unsigned char* lpDataFileOnDisk = NULL;
	Hash128 hashFileOnDisk;

	bool bDoHashesMatch = true;
	bDoHashesMatch = bDoHashesMatch && ReadFileToBuffer(lpszPath, &lpDataFileOnDisk, &dwSizeFileOnDisk) == NO_ERROR;
	bDoHashesMatch = bDoHashesMatch && GenerateMD5Hash(lpDataFileOnDisk, dwSizeFileOnDisk, &hashFileOnDisk) == NO_ERROR;
	bDoHashesMatch = bDoHashesMatch && memcmp(hashFileOnDisk.cbData, hash.cbData, sizeof(hash.cbData)) == 0;

	if (lpDataFileOnDisk != NULL)
		delete[] lpDataFileOnDisk;

	return bDoHashesMatch;
}


// return true on success; return false otherwise
bool UnpackPayload(LPCWSTR lpszPath)
{
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
#ifdef _DEBUG
	FILE* fp;
	AllocConsole();
	freopen_s(&fp, "CONIN$", "r+t", stdin);
	freopen_s(&fp, "CONOUT$", "w+t", stdout);
	freopen_s(&fp, "CONOUT$", "w+t", stderr);
#endif  // _DEBUG

	// get executable path
	WCHAR szExePath[MAX_PATH];
	if (!GetInstallPath(szExePath, sizeof(szExePath) / sizeof(szExePath[0])) ) {  // search the registry
		ErrorMessageBox(L"Failed to locate install directory from registry", NULL);
		return 0;  // according to MSDN, we should return zero before entering the message loop
	}
	DEBUG_MSG(L"Skype path: %s\n", szExePath);

	// generate DLL path in user's Temp directory
	WCHAR szPayloadPath[MAX_PATH];
	GetTempFilePath(szPayloadPath, sizeof(szPayloadPath) / sizeof(szPayloadPath[0]));
	DEBUG_MSG(L"Payload path: %s\n", szPayloadPath);
	if (!UnpackPayload(szPayloadPath)) {
		ErrorMessageBox(L"UnpackPayload()", GetLastError());
		return 0;
	}

	// create process in debug mode
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	if (CreateProcess(szExePath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi) == NULL) {
		DWORD err = GetLastError();
		ErrorMessageBox(L"CreateProcess()", err);
		return err;
	}

	// use debug API to capture events on loading DLLs
	// upon USER32.dll is being loaded, we assume that's Skype trying to fill its IAT
	// so we find some DLL that can only be loaded after USER32.dll and inject our payload at that moment
	DEBUG_EVENT dbgEvent;
	DEBUG_MSG(L"Process attached\n");
	DebugSetProcessKillOnExit(TRUE);  // in case of this program crashes in the debug loop

	bool bDoLoop = true;
	while (bDoLoop) {
		DWORD dwContinueStatus = DBG_CONTINUE;  // continue by default
		if (WaitForDebugEvent(&dbgEvent, INFINITE) == 0) {
			DWORD err = GetLastError();
			ErrorMessageBox(L"WaitForDebugEvent()", err);
			TerminateProcess(pi.hProcess, 0);
			return err;
		}
		DEBUG_MSG(L"Event: 0x%x\n", dbgEvent.dwDebugEventCode);

		switch (dbgEvent.dwDebugEventCode) {
			case CREATE_PROCESS_DEBUG_EVENT:
			{
				CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);

				// install a hardware breakpoint at entry point
				HWBreakpoint32::Enable(pi.hThread, dbgEvent.u.CreateProcessInfo.lpStartAddress, 0);

				break;
			}

			case EXCEPTION_DEBUG_EVENT:
			{
				switch (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode) {
					case EXCEPTION_SINGLE_STEP:  // hardware breakpoint triggered
					{
						// uninstall the hardware breakpoint at entry point
						HWBreakpoint32::Disable(pi.hThread, 0);

						DLLInjector32 injector(pi, szPayloadPath);
						injector.Inject();

						SuspendThread(pi.hThread);
						bDoLoop = false;
						break;
					}
					case EXCEPTION_BREAKPOINT:  // expecting the breakpoint triggered by Windows Debug API for attaching the process
					{
						// do nothing
						break;
					}
					default:
					{
						dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;  // forward if exception is other than a breakpoint
						break;
					}
				}

				break;
			}

			case LOAD_DLL_DEBUG_EVENT:
			{
				CloseHandle(dbgEvent.u.LoadDll.hFile);
				break;
			}

			case EXIT_PROCESS_DEBUG_EVENT:
			{
				bDoLoop = false;
				break;
			}

			default:
			{
				break;
			}
		}
		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dwContinueStatus);
	}

	DebugSetProcessKillOnExit(FALSE);
	DebugActiveProcessStop(pi.dwProcessId);  // detach

	ResumeThread(pi.hThread);

#ifdef _DEBUG
	DEBUG_MSG(L"end, press ENTER to quit\n");
	getchar();

	FreeConsole();
#endif  // _DEBUG

	return NO_ERROR;
}

