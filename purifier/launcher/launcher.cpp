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
#include <string>

#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>

#include <gandr/Buffer.h>
#include <gandr/Handle.h>
#include <gandr/ProcessList.h>

#include "shared/purifier.h"
#include "shared/util.h"
#include "payload.h"



namespace {



// output localized error message if $dwErrCode is non-zero
void ShowErrorMessageBox(LPCWSTR lpszMsg, DWORD dwErrCode)
{
	std::wstring message = L"An error occurred during launching.\n";

	if (dwErrCode != NO_ERROR) {
		gan::AutoHandle systemMsg(static_cast<LPWSTR>(nullptr), ::LocalFree);
		::FormatMessageW(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			nullptr,
			dwErrCode,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			reinterpret_cast<LPWSTR>(&systemMsg.GetRef()),
			0,
			nullptr
		);

		message.reserve(wcslen(systemMsg) + wcslen(lpszMsg) + 128);
		message += L"\nFunction: ";
		message += lpszMsg;
		message += L"\nCode: ";
		message += std::to_wstring(dwErrCode);
		message += L"\nDetail: ";
		message += systemMsg;
	}
	else {
		message.reserve(wcslen(lpszMsg) + 128);
		message += L"\nDetail: ";
		message += lpszMsg;
	}

	::MessageBox(nullptr, message.c_str(), APP_NAME, MB_OK | MB_ICONERROR);
}


// return true on success; return false otherwise
bool UnpackPayloadTo(const std::wstring& path)
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
		auto payloadData = gan::Buffer::Allocate(dwPayloadSize);
		if (payloadData == nullptr)
			return false;
		CopyMemory(*payloadData, s_payloadData, dwPayloadSize);

		// de-obfuscate our code
		for (DWORD i = 0; i < dwPayloadSize; i++)
			(*payloadData)[i] ^= BYTE_OBFUSCATOR;

		// write to a temp path
		gan::AutoWinHandle hFile = ::CreateFile(lpszPath, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		DWORD dwWritten;
		if (hFile != INVALID_HANDLE_VALUE)
		{
			::WriteFile(hFile, *payloadData, dwPayloadSize, &dwWritten, nullptr);
			bSucceeded = true;
		}
	}
	else
		bSucceeded = true;  // file already exists

	return bSucceeded;
}


std::vector<uint32_t> FindProcessByName(const gan::ProcessList& procList, const wchar_t* name)
{
	std::vector<uint32_t> foundList;

	uint32_t idx = 0;
	std::for_each(procList.cbegin(), procList.cend(), [&foundList, name, &idx] (const gan::ProcessInfo& procInfo) {
		if (StrStrI(procInfo.path.c_str(), name) != nullptr) {
			foundList.push_back(idx);
		}
		++idx;
	} );

	return foundList;
}


bool TerminateProcess(DWORD pid)
{
	gan::AutoWinHandle hProc = ::OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
	if (hProc != nullptr && ::TerminateProcess(hProc, NO_ERROR) != 0)
		return true;
	return false;
}


void KillWanderingBrowserHost()
{
	gan::ProcessEnumerator32 procEnum;
	gan::ProcessList procList;
	procEnum.GetProcessList(procList);

	auto foundSkype = FindProcessByName(procList, L"Skype.exe");
	auto foundBrowserHost = FindProcessByName(procList, L"SkypeBrowserHost.exe");

	if (foundSkype.size() == 0) {
		// kill all browser hosts
		for (uint32_t idx : foundBrowserHost) {
			DEBUG_MSG(L"Killing pid: %d\n", procList[idx].pid);
			TerminateProcess(procList[idx].pid);
		}
	}
	else {
		auto foundSvchost = FindProcessByName(procList, L"svchost.exe");

		// kill browser hosts whose parent is svchost
		for (uint32_t idx : foundBrowserHost) {
			const auto itr = std::find_if(foundSvchost.cbegin(), foundSvchost.cend(), [pidParent = procList[idx].pidParent, &procList] (uint32_t idx) -> bool {
				return pidParent == procList[idx].pid;
			} );
			if (itr != foundSvchost.cend()) {
				DEBUG_MSG(L"Killing pid: %d\n", procList[idx].pid);
				TerminateProcess(procList[idx].pid);
			}
		}
	}
}



}  // unnames namespace



int WINAPI wWinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ LPWSTR lpCmdLine, _In_ int)
{
	DebugConsole dbgConsole;

	// clean up before executing SkypeBrowserHost.exe
	KillWanderingBrowserHost();

	// generate DLL path in user's Temp directory
	auto pathPayload = GetPayloadPath();
	DEBUG_MSG(L"Payload path: %s\n", pathPayload.c_str());
	if (!UnpackPayloadTo(pathPayload)) {
		ShowErrorMessageBox(L"UnpackPayloadTo()", GetLastError());
		return 0;
	}

	// get executable paths
	auto pathSkypeExe = GetSkypePath();
	if (pathSkypeExe.empty()) {
		ShowErrorMessageBox(L"Failed to locate install directory from registry", NO_ERROR);
		return 0;  // according to MSDN, we should return zero before entering the message loop
	}
	DEBUG_MSG(L"Skype path: %s\n", pathSkypeExe.c_str());

	// create and purify skype.exe
	auto createdPid = CreatePurifiedProcess(pathSkypeExe.c_str(), lpCmdLine, pathPayload.c_str());
	if (createdPid == 0) {
		auto errCode = GetLastError();
		ShowErrorMessageBox(L"CreatePurifiedProcess()", errCode);
		return errCode;
	}

	return NO_ERROR;
}

