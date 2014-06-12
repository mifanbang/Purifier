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



int wmain(int argc, wchar_t** argv)
{
	if (argc < 3) {
		printf("Too few parameters.\n\n");
		system("pause");
		return -1;
	}

	HANDLE hFile;
	DWORD dummy;
	DWORD dwSizePayload;
	LPBYTE lpDataPayload;
	wchar_t* lpPayloadPath = argv[1];
	wchar_t* lpHeaderPath = argv[2];

	// read payload
	hFile = CreateFile(lpPayloadPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"Failed to open %s for reading: %d\n\n", lpPayloadPath, GetLastError());
		system("pause");
		return -1;
	}
	dwSizePayload = GetFileSize(hFile, NULL);
	lpDataPayload = new BYTE[dwSizePayload];
	ReadFile(hFile, lpDataPayload, dwSizePayload, &dummy, NULL);
	CloseHandle(hFile);

	// write into header file
	FILE* fp = NULL;
	_wfopen_s(&fp, lpHeaderPath, L"w");
	fprintf(fp, "// .rdata section will be merged into .text via linker option /MERGE \n");
	fprintf(fp, "const unsigned char s_payloadData[] = {");
	for (DWORD i = 0; i < dwSizePayload; i++) {
		fprintf(fp, "%d,", lpDataPayload[i] ^ BYTE_OBFUSCATOR);
		if ((i & 0xFF) == 0xFF && i != (dwSizePayload - 1))
			fprintf(fp, "\n\t");
	}
	fprintf(fp, "};\n");
	fclose(fp);

	delete[] lpDataPayload;

	wprintf(L"Packing completed successfully.\nThe output is: %s\n\n", lpHeaderPath);

	return 0;
}
