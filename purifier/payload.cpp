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



template <typename T, typename... Arg>
class ThreadSafeResource
{
public:
	ThreadSafeResource(Arg&&... arg)
		: m_resInst(std::forward<Arg>(arg)...)
	{
		InitializeCriticalSection(&m_lock);
	}

	~ThreadSafeResource()
	{
		DeleteCriticalSection(&m_lock);
	}

	template <typename F>
	auto ApplyOperation(F& func) -> decltype(std::declval<F>()(m_resInst))
	{
		using RetType = decltype(std::declval<F>()(m_resInst));

		EnterCriticalSection(&m_lock);
		RetType result = func(m_resInst);
		LeaveCriticalSection(&m_lock);

		return result;
	}


	T m_resInst;
	CRITICAL_SECTION m_lock;
};


using WindowProcMap = std::unordered_map<HWND, WNDPROC>;
ThreadSafeResource<WindowProcMap> s_oriWndProcMap;



// callback function that is set as TChatBanner's window procedure
LRESULT CALLBACK AdWindowProc(
	_In_  HWND hwnd,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
)
{
	LRESULT result = s_oriWndProcMap.ApplyOperation([=] (WindowProcMap& oriWndProcMap) -> LRESULT {
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


// hook function for CreateWindowExW() in user32.dll
HWND WINAPI MyCreateWindowExW(
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
	DWORD dwResult = NULL;
	CallTrampoline32(CreateWindowExW, dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	__asm mov dwResult, eax

	if ((reinterpret_cast<DWORD>(lpClassName) & 0xFFFF0000) != 0) {
		DEBUG_MSG(L"MyCreateWindowExW: %s\n", lpClassName);
		HWND hWnd = (HWND)dwResult;

		if (_wcsicmp(lpClassName, SK_AD_CLASS_NAME) == 0 && hWnd != NULL) {
			s_oriWndProcMap.ApplyOperation([=] (WindowProcMap& oriWndProcMap) -> int {
				oriWndProcMap[hWnd] = (WNDPROC)GetWindowLong(hWnd, GWL_WNDPROC);
				return 0;
			});
			SetWindowLong(hWnd, GWL_WNDPROC, (LONG)AdWindowProc);

			// forces AdWindowProc() to be called right after window creation
			SendMessage(hWnd, WM_SIZE, 0, MAKELPARAM(100, 100));  // lParam can be anything other than MAKELPARAM(0, 0)
		}
	}

	return (HWND)dwResult;
}


// hook function for HttpOpenRequestW() in wininet.dll
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
	if (StrStrI(lpszObjectName, SK_AD_HTTP_REQ_NAME) != NULL) {
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
	static InlineHooking32* s_pHookCreateWindowExW = nullptr;

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

		if (s_pHookCreateWindowExW == nullptr)
			s_pHookCreateWindowExW = new InlineHooking32(CreateWindowExW, MyCreateWindowExW);
		s_pHookCreateWindowExW->Hook();
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
#ifdef _DEBUG
		FreeConsole();
#endif  // _DEBUG

		// unhooks
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
