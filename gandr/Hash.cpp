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

#include "Hash.h"

#include <memory>

#include <windows.h>
#include <bcrypt.h>  // must include after windows.h

#include "Handle.h"


namespace gan {



DWORD Hasher::GetSHA(const void* data, size_t size, Hash<256>& out)
{
	AutoHandle hProv(static_cast<BCRYPT_ALG_HANDLE>(nullptr), [](auto prov) { ::BCryptCloseAlgorithmProvider(prov, 0); });
	AutoHandle hHash(static_cast<BCRYPT_HASH_HANDLE>(nullptr), ::BCryptDestroyHash);

	// initialization of service provider
	bool isSuccessful = true;
	ULONG numByteRead = 0;
	uint32_t hashObjSize = 1;
	isSuccessful = isSuccessful && BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&hProv.GetRef(), BCRYPT_SHA256_ALGORITHM, nullptr, 0));
	isSuccessful = isSuccessful && BCRYPT_SUCCESS(::BCryptGetProperty(hProv, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjSize), sizeof(hashObjSize), &numByteRead, 0));

	// hash calculation
	std::unique_ptr<uint8_t[]> hashObj(new uint8_t[hashObjSize]);
	Hash<256> hash = { { 0 } };
	isSuccessful = isSuccessful && BCRYPT_SUCCESS(::BCryptCreateHash(hProv, &hHash.GetRef(), hashObj.get(), hashObjSize, nullptr, 0, 0));
	isSuccessful = isSuccessful && BCRYPT_SUCCESS(::BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<void*>(data)), size, 0));
	isSuccessful = isSuccessful && BCRYPT_SUCCESS(::BCryptFinishHash(hHash, reinterpret_cast<PUCHAR>(&hash.data), sizeof(hash), 0));
	if (!isSuccessful)
		return GetLastError();

	::CopyMemory(&out, &hash, sizeof(hash));
	return NO_ERROR;
}



}  // namespace gan

