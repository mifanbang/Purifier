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

#include <windows.h>
#include <wincrypt.h>

#include "util.h"



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
