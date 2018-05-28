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

#include "util.h"

#include <functional>

#include <windows.h>
#include <wincrypt.h>

#include <gandr/Debugger.h>
#include <gandr/DllPreloadDebugSession.h>
#include <gandr/Handle.h>

#include "purifier.h"



// ---------------------------------------------------------------------------
// debug utilities
// ---------------------------------------------------------------------------

DebugConsole::DebugConsole()
{
	FILE* fp;
	::AllocConsole();
	freopen_s(&fp, "CONIN$", "r+t", stdin);
	freopen_s(&fp, "CONOUT$", "w+t", stdout);
	freopen_s(&fp, "CONOUT$", "w+t", stderr);
}


DebugConsole::~DebugConsole()
{
	DEBUG_MSG(L"I'm done\n");
	system("pause");

	::FreeConsole();
}


// ---------------------------------------------------------------------------
// hash functions
// ---------------------------------------------------------------------------

std::unique_ptr<gan::Buffer> ReadFileToBuffer(const wchar_t* lpPath, WinErrorCode& errCode)
{
	gan::AutoWinHandle hFile = ::CreateFile(lpPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, nullptr);
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD dwSizePayload = ::GetFileSize(hFile, nullptr);

		auto fileContent = gan::Buffer::Allocate(dwSizePayload);
		DWORD dwSizeRead;
		if (fileContent != nullptr && ::ReadFile(hFile, *fileContent, dwSizePayload, &dwSizeRead, nullptr) == TRUE) {
			errCode = NO_ERROR;
			return std::move(fileContent);
		}
	}

	errCode = ::GetLastError();
	return std::unique_ptr<gan::Buffer>();
}


WinErrorCode GenerateMD5Hash(const unsigned char* lpData, unsigned int uiDataSize, Hash128* lpOutHash)
{
	gan::AutoHandle hProv(static_cast<HCRYPTPROV>(0), [](auto prov) { ::CryptReleaseContext(prov, 0); });
	gan::AutoHandle hHash(static_cast<HCRYPTHASH>(0), ::CryptDestroyHash);
	unsigned char cbHash[16];
	DWORD dwHashSize = sizeof(cbHash);

	bool isSuccessful = true;
	isSuccessful = isSuccessful && ::CryptAcquireContextW(&hProv.GetRef(), nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) != FALSE;
	isSuccessful = isSuccessful && ::CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash.GetRef()) != FALSE;
	isSuccessful = isSuccessful && ::CryptHashData(hHash, lpData, uiDataSize, 0) != FALSE;
	isSuccessful = isSuccessful && ::CryptGetHashParam(hHash, HP_HASHVAL, cbHash, &dwHashSize, 0) != FALSE;
	if (!isSuccessful)
		return GetLastError();

	::CopyMemory(lpOutHash->cbData, cbHash, sizeof(cbHash));
	return NO_ERROR;
}


bool CheckFileHash(const wchar_t* lpszPath, const Hash128& hash)
{
	std::unique_ptr<gan::Buffer> fileContent;
	WinErrorCode errCode;
	Hash128 hashFileOnDisk;

	bool bDoHashesMatch = true;
	bDoHashesMatch = bDoHashesMatch && (fileContent = ReadFileToBuffer(lpszPath, errCode)).get() != nullptr;
	bDoHashesMatch = bDoHashesMatch && GenerateMD5Hash(*fileContent, fileContent->GetSize(), &hashFileOnDisk) == NO_ERROR;
	bDoHashesMatch = bDoHashesMatch && memcmp(hashFileOnDisk.cbData, hash.cbData, sizeof(hash.cbData)) == 0;

	return bDoHashesMatch;
}


// ---------------------------------------------------------------------------
// process creation function
// ---------------------------------------------------------------------------

namespace {

#ifdef _DEBUG
	// just for the purpose to override OnPreEvent()
	class PurifierDLLPreloadDebugSession : public gan::DLLPreloadDebugSession
	{
	public:
		PurifierDLLPreloadDebugSession(const CreateProcessParam& newProcParam, const wchar_t* pPayloadPath)
			: gan::DLLPreloadDebugSession(newProcParam, pPayloadPath)
		{ }

	private:
		virtual void OnPreEvent(const PreEvent& event) override
		{
			DEBUG_MSG(L"Event: 0x%x\n", event.eventCode);
		}
	};

#else
	using PurifierDLLPreloadDebugSession = gan::DLLPreloadDebugSession;

#endif  // _DEBUG
}  // unnamed namespace


uint32_t CreatePurifiedProcess(const wchar_t* szExePath, const wchar_t* szArg, const wchar_t* szPayloadPath)
{
	gan::Debugger debugger;

	gan::DebugSession::CreateProcessParam createParam;
	createParam.imagePath = szExePath;
	createParam.args = szArg;
	if (!debugger.AddSession<PurifierDLLPreloadDebugSession>(createParam, szPayloadPath))
		return 0;

	// cache pid
	gan::Debugger::IdList pidList;
	debugger.GetSessionList(pidList);

	if (debugger.EnterEventLoop() == gan::Debugger::EventLoopResult::ErrorOccurred)
		return 0;

	return pidList[0];
}


// ---------------------------------------------------------------------------
// misc functions
// ---------------------------------------------------------------------------

std::wstring GetPayloadPath()
{
	WCHAR buffer[MAX_PATH];
	::GetTempPathW(sizeof(buffer) / sizeof(buffer[0]), buffer);
	wcsncat_s(buffer, sizeof(buffer) / sizeof(buffer[0]), APP_NAME L"-" APP_VERSION L".dll", _TRUNCATE);

	return std::wstring(buffer);
}


std::wstring GetSkypePath()
{
	std::wstring pathSkypeExe;

	HKEY hRegKey;
	DWORD dwSize = MAX_PATH;
	wchar_t szPath[MAX_PATH];

	if (::RegOpenKeyW(HKEY_CURRENT_USER, L"SOFTWARE\\Skype\\Phone", &hRegKey) == NO_ERROR) {
		if (::RegQueryValueExW(hRegKey, L"SkypePath", nullptr, nullptr, reinterpret_cast<PBYTE>(szPath), &dwSize) == NO_ERROR)
			pathSkypeExe = szPath;
		::RegCloseKey(hRegKey);
	}

	return pathSkypeExe;
}


std::wstring GetBrowserHostPath()
{
	std::wstring pathBrowserHostExe;

	HKEY hRegKey;
	DWORD dwSize = MAX_PATH;
	wchar_t szPath[MAX_PATH];

	if (::RegOpenKeyW(HKEY_CLASSES_ROOT, L"CLSID\\{3FCB7074-EC9E-4AAF-9BE3-C0E356942366}\\LocalServer32", &hRegKey) == NO_ERROR) {
		if (::RegQueryValueExW(hRegKey, nullptr, nullptr, nullptr, reinterpret_cast<PBYTE>(szPath), &dwSize) == NO_ERROR) {
			if (szPath[0] == '"')
				pathBrowserHostExe = szPath + 1;
			else
				pathBrowserHostExe = szPath;

			if (pathBrowserHostExe.back() == '\"')
				pathBrowserHostExe.pop_back();
		}
		::RegCloseKey(hRegKey);
	}

	return pathBrowserHostExe;
}


std::wstring GetBrowserHostEventName(uint32_t pid)
{
	return EVENT_BROWSERHOST_SYNC + std::to_wstring(pid);
}
