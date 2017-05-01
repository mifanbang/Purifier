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

#include <algorithm>
#include <array>

#include <windows.h>
#include <wininet.h>

#include "purifier.h"

#include "detours/user32.h"
#include "detours/wininet.h"
#include "hooking.h"
#include "util.h"



static bool IsInsideTarget()
{
	static const std::array<const wchar_t*, 2> targetImages = {{
		L"skype.exe",
		L"SkypeBrowserHost.exe"
	}};

	return std::any_of(targetImages.cbegin(), targetImages.cend(), GetModuleHandle);
}



BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID)
{
	static DebugConsole* pDbgConsole = nullptr;
	static InlineHooking32* s_pHookHttpOpenRequestW = nullptr;
	static InlineHooking32* s_pHookCreateWindowExW = nullptr;

	if (fdwReason == DLL_PROCESS_ATTACH) {
		pDbgConsole = new DebugConsole;

		// checks if the injected process is correct
		if (!IsInsideTarget()) {
			MessageBox(NULL, L"This DLL can only be loaded by a Skype process.", APP_NAME, MB_OK | MB_ICONERROR);
			return FALSE;
		}

		// hook
		if (s_pHookHttpOpenRequestW == nullptr)
			s_pHookHttpOpenRequestW = new InlineHooking32(HttpOpenRequestW, detour::HttpOpenRequestW);
		s_pHookHttpOpenRequestW->Hook();

		if (s_pHookCreateWindowExW == nullptr)
			s_pHookCreateWindowExW = new InlineHooking32(CreateWindowExW, detour::CreateWindowExW);
		s_pHookCreateWindowExW->Hook();
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
		if (pDbgConsole != nullptr) {
			delete pDbgConsole;
			pDbgConsole = nullptr;
		}

		// unhook
		if (s_pHookHttpOpenRequestW != nullptr) {
			s_pHookHttpOpenRequestW->Unhook();
			delete s_pHookHttpOpenRequestW;
			s_pHookHttpOpenRequestW = nullptr;
		}

		if (s_pHookCreateWindowExW != nullptr) {
			s_pHookCreateWindowExW->Unhook();
			delete s_pHookCreateWindowExW;
			s_pHookCreateWindowExW = nullptr;
		}
	}

	return TRUE;
}
