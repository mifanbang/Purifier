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

#include <unordered_map>

#include <shlwapi.h>

#include <gandr/hooking.h>
#include <gandr/Mutex.h>

#include "purifier.h"
#include "util.h"
#include "user32.h"


namespace detour {



static bool IsAdWindow(const wchar_t* className)
{
	const wchar_t* SK_AD_CLASS_NAME = L"TChatBanner";

	return StrCmpIW(className, SK_AD_CLASS_NAME) == 0;
}



using WindowProcMap = std::unordered_map<HWND, WNDPROC>;
static gan::ThreadSafeResource<WindowProcMap> s_oriWndProcMap;



// callback function that is set as TChatBanner's window procedure
LRESULT CALLBACK AdWindowProc(
	_In_  HWND hwnd,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
)
{
	LRESULT result = s_oriWndProcMap.ApplyOperation([hwnd, uMsg, wParam, lParam] (WindowProcMap& oriWndProcMap) -> LRESULT {
		auto itr = oriWndProcMap.find(hwnd);
		if (itr == oriWndProcMap.end())
			return DefWindowProc(hwnd, uMsg, wParam, lParam);  // this shouldn't happen though
		WNDPROC pWndProc = itr->second;

		// certain messages must be processed
		if (uMsg == WM_SIZE) {
			// filters size-setting messages
			unsigned int newWidth = LOWORD(lParam);
			unsigned int newHeight = HIWORD(lParam);
			DEBUG_MSG(L"AdWindowProc: %d %d\n", newWidth, newHeight);

			if ((newWidth | newHeight) != 0) {
				MoveWindow(hwnd, 0, 0, 0, 0, TRUE);
				return 0;  // blocks the message. must return 0
			}
		}
		else if (uMsg == WM_NCDESTROY) {
			// clears the entry in wndproc table to avoid memory leaks
			oriWndProcMap.erase(itr);
		}
	
		return pWndProc(hwnd, uMsg, wParam, lParam);
	});

	return result;
}


HWND WINAPI CreateWindowExW(
	_In_      DWORD dwExStyle,
	_In_opt_  LPCWSTR lpClassName,
	_In_opt_  LPCWSTR lpWindowName,
	_In_      DWORD dwStyle,
	_In_      int x,
	_In_      int y,
	_In_      int nWidth,
	_In_      int nHeight,
	_In_opt_  HWND hWndParent,
	_In_opt_  HMENU hMenu,
	_In_opt_  HINSTANCE hInstance,
	_In_opt_  LPVOID lpParam
)
{
	auto hWnd = CallTram32(::CreateWindowExW)(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);

	if ((reinterpret_cast<DWORD>(lpClassName) & 0xFFFF0000) != 0) {
		DEBUG_MSG(L"CreateWindowExW: %s\n", lpClassName);

		if (IsAdWindow(lpClassName) && hWnd != nullptr) {
			s_oriWndProcMap.ApplyOperation([hWnd] (WindowProcMap& oriWndProcMap) -> int {
				oriWndProcMap[hWnd] = (WNDPROC)GetWindowLong(hWnd, GWL_WNDPROC);
				return 0;
			} );
			SetWindowLong(hWnd, GWL_WNDPROC, (LONG)AdWindowProc);

			// forces AdWindowProc() to be called right after window creation
			SendMessage(hWnd, WM_SIZE, 0, MAKELPARAM(100, 100));  // lParam can be anything other than MAKELPARAM(0, 0)
		}
	}

	return hWnd;
}



}  // detour
