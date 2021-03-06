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

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include "shared/purifier.h"
#include "shared/util.h"



int wmain(int argc, wchar_t** argv)
{
	if (argc < 3) {
		printf("Too few parameters.\n\n");
		system("pause");
		return -1;
	}

	WinErrorCode errCode;
	const wchar_t* lpPayloadPath = argv[1];
	const wchar_t* lpHeaderPath = argv[2];

	// read payload
	auto payloadData = ReadFileToBuffer(lpPayloadPath, errCode);
	if (payloadData == nullptr) {
		wprintf(L"Failed to open %s for reading: %d\n\n", lpPayloadPath, errCode);
		return -1;
	}

	// generate hash of payload
	gan::Hash<256> hash;
	if ((errCode = gan::Hasher::GetSHA(*payloadData, payloadData->GetSize(), hash)) != NO_ERROR) {
		wprintf(L"Failed to create hash for payload: %d\n\n", errCode);
		return -1;
	}

	// output to intermediate header file
	FILE* fp = nullptr;
	if (_wfopen_s(&fp, lpHeaderPath, L"w") != 0 || fp == nullptr) {
		wprintf(L"Failed to open header file to write.\n\n");
		return -1;
	}

	// pre-defined directives
	fprintf(fp, "#pragma once\n");
	fprintf(fp, "#include \"shared/util.h\"\n\n");

	// payload data
	fprintf(fp, "// .rdata section will be merged into .text via linker option /MERGE \n");
	fprintf(fp, "const unsigned char s_payloadData[] = {");
	for (DWORD i = 0, dwSizePayload = payloadData->GetSize(); i < dwSizePayload; i++) {
		fprintf(fp, "%d,", (*payloadData)[i] ^ c_byteObfuscator);
		if ((i & 0xFF) == 0xFF && i != (dwSizePayload - 1))
			fprintf(fp, "\n\t");
	}
	fprintf(fp, "};\n\n");

	// hash of payload
	fprintf(fp, "// SHA256 digest of non-obfuscated payload data\n");
	fprintf(fp, "const gan::Hash<256> s_payloadHash = {{");
	for (DWORD i = 0; i < sizeof(hash.data); i++)
		fprintf(fp, "%d%s", hash.data[i], i < sizeof(hash.data) - 1 ? "," : "");
	fprintf(fp, "}};\n");

	fclose(fp);

	wprintf(L"Packing completed successfully.\nThe output is: %s\n\n", lpHeaderPath);

	return 0;
}
