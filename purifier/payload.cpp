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
#include <wininet.h>
#include <shlwapi.h>

#ifdef _DEBUG
	#include <stdio.h>
	#define DEBUG_MSG	wprintf
#else
	#define DEBUG_MSG
#endif  // _DEBUG

#include "purifier.h"
#include "hooking.h"



// hooking function for HttpOpenRequestW() in wininet.dll
HINTERNET WINAPI MyHttpOpenRequestW(
  _In_  HINTERNET hConnect,
  _In_  LPCWSTR lpszVerb,
  _In_  LPCWSTR lpszObjectName,
  _In_  LPCWSTR lpszVersion,
  _In_  LPCWSTR lpszReferer,
  _In_  LPCWSTR* lplpszAcceptTypes,
  _In_  DWORD dwFlags,
  _In_  DWORD_PTR dwContext
)
{
	DEBUG_MSG(L"MyHttpOpenRequestW: %s %s\n", lpszVerb, lpszObjectName);

	// checks for blockage
	if (StrStrI(lpszObjectName, SK_AD_HTTP_REQ_NAME) != NULL)
	{
		SetLastError(ERROR_INTERNET_INVALID_URL);  // fakes an error
		return NULL;
	}

	// calls the original function with the help of a trampoline
	DWORD dwResult = NULL;
	CallTrampoline32(HttpOpenRequestW, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
	__asm mov dwResult, eax

	return (HINTERNET)dwResult;
}


BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID)
{
	static InlineHooking32* s_pHookHttpOpenRequestW = nullptr;

	if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef _DEBUG
		FILE* fp;
		AllocConsole();
		freopen_s(&fp, "CONIN$", "r+t", stdin);
		freopen_s(&fp, "CONOUT$", "w+t", stdout);
#endif  // _DEBUG

		// checks if the injected process is correct
		if (GetModuleHandle(SK_MODULE_NAME) == NULL) {
			MessageBox(NULL, L"This DLL can only be loaded to Skype.", APP_NAME, MB_OK | MB_ICONERROR);
			return FALSE;
		}

		// hooks
		if (s_pHookHttpOpenRequestW == nullptr)
			s_pHookHttpOpenRequestW = new InlineHooking32(HttpOpenRequestW, MyHttpOpenRequestW);
		s_pHookHttpOpenRequestW->Hook();
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
#ifdef _DEBUG
		FreeConsole();
#endif  // _DEBUG

		// unhooks
		if (s_pHookHttpOpenRequestW != nullptr) {
			s_pHookHttpOpenRequestW->Unhook();
			delete s_pHookHttpOpenRequestW;
		}
	}

	return TRUE;
}
