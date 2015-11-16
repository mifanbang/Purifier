/*
*  purifier - removing ad banners in Microsoft Skype
*  Copyright (C) 2011-2015 Mifan Bang <http://debug.tw>.
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

#include "util.h"

#include "DllInjector.h"



DLLInjector32::DLLInjector32(const PROCESS_INFORMATION& procInfo, LPCWSTR lpszDllPath)
	: m_procInfo(procInfo)
	, m_dllPath(lpszDllPath)
{
	HANDLE hCurrentProc = GetCurrentProcess();
	HANDLE hDuplicated = INVALID_HANDLE_VALUE;

	DuplicateHandle(hCurrentProc, procInfo.hProcess, hCurrentProc, &hDuplicated, 0, FALSE, DUPLICATE_SAME_ACCESS);
	m_procInfo.hProcess = hDuplicated;

	DuplicateHandle(hCurrentProc, procInfo.hThread, hCurrentProc, &hDuplicated, 0, FALSE, DUPLICATE_SAME_ACCESS);
	m_procInfo.hThread = hDuplicated;
}


DLLInjector32::~DLLInjector32()
{
	CloseHandle(m_procInfo.hProcess);
	CloseHandle(m_procInfo.hThread);
}


DLLInjector32::InjectionResult DLLInjector32::Inject()
{
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));

	// make a copy of interested registers
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(m_procInfo.hThread, &ctx);

	// write DLL path string to the remote process
	DWORD dwBufferSize = sizeof(WCHAR) * (m_dllPath.length() + 1);
	LPWSTR lpBufferRemote = (LPWSTR)VirtualAllocEx(m_procInfo.hProcess, NULL, dwBufferSize, MEM_COMMIT, PAGE_READWRITE);
	bool isDllPathWritten = (lpBufferRemote != NULL && WriteProcessMemory(m_procInfo.hProcess, lpBufferRemote, m_dllPath.data(), dwBufferSize, NULL) != NULL);
	if (!isDllPathWritten)
		return InjectionResult::Error_DLLPathNotWritten;

	// write fake stack frame
	struct StackFrameForLoadLibraryW
	{
		LPVOID pRetAddr;
		LPWSTR pDllPath;
	};
	StackFrameForLoadLibraryW fakeStackFrame = { reinterpret_cast<LPVOID>(ctx.Eip), lpBufferRemote };
	if (WriteProcessMemory(m_procInfo.hProcess, reinterpret_cast<LPVOID>(ctx.Esp), &fakeStackFrame, sizeof(fakeStackFrame), NULL) == NULL)
		return InjectionResult::Error_StackFrameNotWritten;

	// manipulate EIP to fake a function call
	DynamicCall32<decltype(LoadLibraryW)> funcLoadLibraryW(L"kernel32", "LoadLibraryW");
	ctx.ContextFlags = CONTEXT_CONTROL;
	ctx.Eip = reinterpret_cast<DWORD>(funcLoadLibraryW.GetAddress());
	if (SetThreadContext(m_procInfo.hThread, &ctx) == FALSE)
		return InjectionResult::Error_ContextNotSet;

	return InjectionResult::Succeeded;
}
