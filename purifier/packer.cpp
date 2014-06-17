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
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include "purifier.h"
#include "util.h"



int wmain(int argc, wchar_t** argv)
{
	if (argc < 3) {
		printf("Too few parameters.\n\n");
		system("pause");
		return -1;
	}

	unsigned int uiLastError = NO_ERROR;
	unsigned int dwSizePayload;
	unsigned char* lpDataPayload;
	const wchar_t* lpPayloadPath = argv[1];
	const wchar_t* lpHeaderPath = argv[2];

	// read payload
	if ((uiLastError = ReadFileToBuffer(lpPayloadPath, &lpDataPayload, &dwSizePayload)) != NO_ERROR) {
		wprintf(L"Failed to open %s for reading: %d\n\n", lpPayloadPath, uiLastError);
		return -1;
	}

	// generate hash of payload
	unsigned char cbHash[16];
	if ((uiLastError = GenerateMD5Hash(lpDataPayload, dwSizePayload, cbHash)) != NO_ERROR) {
		wprintf(L"Failed to create hash for payload: %d\n\n", uiLastError);
		return -1;
	}

	// output to intermediate header file
	FILE* fp = NULL;
	_wfopen_s(&fp, lpHeaderPath, L"w");

	// payload data
	fprintf(fp, "// .rdata section will be merged into .text via linker option /MERGE \n");
	fprintf(fp, "const unsigned char s_payloadData[] = {");
	for (DWORD i = 0; i < dwSizePayload; i++) {
		fprintf(fp, "%d,", lpDataPayload[i] ^ BYTE_OBFUSCATOR);
		if ((i & 0xFF) == 0xFF && i != (dwSizePayload - 1))
			fprintf(fp, "\n\t");
	}
	fprintf(fp, "};\n\n");

	// hash of payload
	fprintf(fp, "// MD5 digest of non-obfuscated payload data\n");
	fprintf(fp, "const unsigned char s_payloadHash[] = {");
	for (DWORD i = 0; i < sizeof(cbHash); i++)
		fprintf(fp, "%d,", cbHash[i]);
	fprintf(fp, "};\n");

	fclose(fp);

	delete[] lpDataPayload;

	wprintf(L"Packing completed successfully.\nThe output is: %s\n\n", lpHeaderPath);

	return 0;
}
