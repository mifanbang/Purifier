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
	hFile = CreateFile(lpPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD dummy;
		DWORD dwSizePayload;
		LPBYTE lpDataPayload;

		dwSizePayload = GetFileSize(hFile, NULL);
		lpDataPayload = new BYTE[dwSizePayload];
		dummy = ReadFile(hFile, lpDataPayload, dwSizePayload, &dummy, NULL);
		CloseHandle(hFile);

		*lpOutPtr = lpDataPayload;
		*lpOutBufferSize = dwSizePayload;
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
	isSuccessful = isSuccessful && CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) != FALSE;
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


// ---------------------------------------------------------------------------
// hardware breakpoint class and its helper functions
// ---------------------------------------------------------------------------

static DWORD* GetRegisterFromSlot(CONTEXT& ctx, unsigned int nSlot)
{
	return nSlot < 4 ? &ctx.Dr0 + nSlot : nullptr;
}


static DWORD GetMaskFromSlot(unsigned int nSlot)
{
	if (nSlot < 4)
		return 1 << (nSlot << 1);
	return 0;
}


enum class Dr7UpdateOperation
{
	Enable,
	Disable
};

static bool UpdateDebugRegisters(HANDLE hThread, LPVOID pAddress, unsigned int nSlot, Dr7UpdateOperation opDr7)
{
	if (nSlot >= 4)
		return false;

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(hThread, &ctx) == 0)
		return false;

	DWORD* pReg = GetRegisterFromSlot(ctx, nSlot);
	*pReg = reinterpret_cast<DWORD>(pAddress);
	if (opDr7 == Dr7UpdateOperation::Enable)
		ctx.Dr7 |= GetMaskFromSlot(nSlot);
	else
		ctx.Dr7 &= ~GetMaskFromSlot(nSlot);
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (SetThreadContext(hThread, &ctx) == 0)
		return false;

	return true;
}


bool HWBreakpoint32::Enable(HANDLE hThread, LPVOID pAddress, unsigned int nSlot)
{
	return UpdateDebugRegisters(hThread, pAddress, nSlot, Dr7UpdateOperation::Enable);
}


bool HWBreakpoint32::Disable(HANDLE hThread, unsigned int nSlot)
{
	return UpdateDebugRegisters(hThread, nullptr, nSlot, Dr7UpdateOperation::Disable);
}
