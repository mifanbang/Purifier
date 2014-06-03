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
#include <psapi.h>

#ifdef _DEBUG
	#include <stdio.h>
	#define DEBUG_MSG	wprintf
#else
	#define DEBUG_MSG
#endif  // _DEBUG

#include <vector>

#include "purifier.h"


typedef std::pair<DWORD, DWORD>	PatchEntry;
typedef std::vector<PatchEntry>	PatchList;


HMODULE g_hModSkype = NULL;  // handle to the "skype.exe" module

DWORD g_dwCreateWindowExW = NULL;  // address of the real CreateWindowExW()
DWORD g_dwMessageBoxW = NULL;  // address of the real MessageBoxW()



HWND WINAPI MyCreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	if (_wcsicmp(SK_AD_WINDOW_NAME, lpClassName) == 0)
		return NULL;
	else
		return CreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}


int MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	if (_wcsicmp(SK_OS_ERROR_MSG, lpText) == 0)
		return IDOK;
	else if (wcsstr(lpText, SK_CLASS_ERROR_MSG) != NULL)
		return IDOK;
	else
		return MessageBoxW(hWnd, lpText, lpCaption, uType);
}


__declspec(dllexport) void WINAPI DummyFunc()
{
	// do nothing
	// We export the function for the purpose to make VC++ produce .lib file for payload.dll
	// so that other projects in the same solution can have dependency on it.
}


// search and patch PAGE_EXECUTE_WRITECOPY memory regions in $hMod according to entries in $list
bool PatchMemory(HMODULE hMod, PatchList& list)
{
	MODULEINFO modInfo;
	if (GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)) == 0)
		return false;

	bool bIsPatched = false;
	LPDWORD lpDwordPointer = (LPDWORD)modInfo.lpBaseOfDll;
	unsigned int uSizeInDword = modInfo.SizeOfImage >> 2;
	while ((DWORD)lpDwordPointer < (DWORD)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {
		MEMORY_BASIC_INFORMATION memInfo;
		VirtualQuery((LPCVOID)lpDwordPointer, &memInfo, sizeof(memInfo));

		// IAT is PAGE_EXECUTE_WRITECOPY
		if ((memInfo.AllocationProtect & PAGE_EXECUTE_WRITECOPY) && (memInfo.State & MEM_COMMIT)) {
			for (DWORD i = 0; i < memInfo.RegionSize >> 2; i++, lpDwordPointer++) {

				// iterate through the list
				for (size_t j = 0; j < list.size(); j++) {
					if (*lpDwordPointer == list[j].first) {
						bIsPatched = true;
						*lpDwordPointer = list[j].second;
						break;  // prevent modified value from matching other entries
					}
				}
			}
		}

		lpDwordPointer = (LPDWORD)((DWORD)memInfo.BaseAddress + memInfo.RegionSize);
	}

	return bIsPatched;
}


BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID)
{
	if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef _DEBUG
		FILE* fp;
		AllocConsole();
		freopen_s(&fp, "CONIN$", "r+t", stdin);
		freopen_s(&fp, "CONOUT$", "w+t", stdout);
#endif  // _DEBUG
		g_hModSkype = GetModuleHandle(SK_MODULE_NAME);
		if (g_hModSkype == NULL) {
			MessageBox(NULL, L"This DLL can only be loaded to Skype.", APP_NAME, MB_OK | MB_ICONERROR);
			return FALSE;
		}

		// CreateWindowExW
		g_dwCreateWindowExW = (DWORD) GetProcAddress(GetModuleHandle(L"user32"), "CreateWindowExW");
		if (g_dwCreateWindowExW == NULL) {
			MessageBox(NULL, L"Unable to obatin address of CreateWindowExW.", APP_NAME, MB_OK | MB_ICONERROR);
			return FALSE;
		}

		// MessageBoxW
		g_dwMessageBoxW = (DWORD) GetProcAddress(GetModuleHandle(L"user32"), "MessageBoxW");
		if (g_dwMessageBoxW == NULL) {
			MessageBox(NULL, L"Unable to obatin address of MessageBoxW.", APP_NAME, MB_OK | MB_ICONERROR);
			return FALSE;
		}

		// patch import address
		PatchList list;
		list.push_back(PatchEntry(g_dwCreateWindowExW, (DWORD)MyCreateWindowExW));
		list.push_back(PatchEntry(g_dwMessageBoxW, (DWORD)MyMessageBoxW));
		if (!PatchMemory(g_hModSkype, list)) {
			MessageBox(NULL, L"Memory patch failed. Maybe you're using a new Skype version.", APP_NAME, MB_OK | MB_ICONERROR);
			return FALSE;
		}
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
#ifdef _DEBUG
		FreeConsole();

		// patch import address to the original one
		if (g_hModSkype != NULL && MyCreateWindowExW != NULL) {
			PatchList list;
			list.push_back(PatchEntry((DWORD)MyCreateWindowExW, g_dwCreateWindowExW));
			list.push_back(PatchEntry((DWORD)MyMessageBoxW, g_dwMessageBoxW));
			PatchMemory(g_hModSkype, list);
		}
#endif  // _DEBUG
	}

	return TRUE;
}
