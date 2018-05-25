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

#include "DllInjector.h"

#include <functional>
#include <memory>

#include "DynamicCall.h"
#include "Handle.h"



namespace gan {



DLLInjectorByContext32::DLLInjectorByContext32(HANDLE hProcess, HANDLE hThread)
	: m_hProcess(INVALID_HANDLE_VALUE)
	, m_hThread(INVALID_HANDLE_VALUE)
{
	HANDLE hCurrentProc = GetCurrentProcess();
	HANDLE hDuplicated = INVALID_HANDLE_VALUE;

	::DuplicateHandle(hCurrentProc, hProcess, hCurrentProc, &hDuplicated, 0, FALSE, DUPLICATE_SAME_ACCESS);
	m_hProcess = hDuplicated;

	::DuplicateHandle(hCurrentProc, hThread, hCurrentProc, &hDuplicated, 0, FALSE, DUPLICATE_SAME_ACCESS);
	m_hThread = hDuplicated;
}


DLLInjectorByContext32::~DLLInjectorByContext32()
{
	::CloseHandle(m_hProcess);
	::CloseHandle(m_hThread);
}


DLLInjectorByContext32::InjectionResult DLLInjectorByContext32::Inject(LPCWSTR pDllPath)
{
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));

	// make a copy of registers of interest
	ctx.ContextFlags = CONTEXT_CONTROL;
	::GetThreadContext(m_hThread, &ctx);

	// allocate remote buffer and write DLL path to it
	DWORD dwBufferSize = sizeof(WCHAR) * (wcslen(pDllPath) + 1);
	AutoHandle remoteBuffer(
		reinterpret_cast<LPWSTR>(::VirtualAllocEx(m_hProcess, nullptr, dwBufferSize, MEM_COMMIT, PAGE_READWRITE)),
		[hProc = this->m_hProcess](LPWSTR data) {
			::VirtualFreeEx(hProc, data, 0, MEM_RELEASE);
		}
	);
	bool isDllPathWritten = (remoteBuffer && ::WriteProcessMemory(m_hProcess, remoteBuffer, pDllPath, dwBufferSize, nullptr) != 0);
	if (!isDllPathWritten)
		return InjectionResult::Error_DLLPathNotWritten;

	// write faked stack frame
	struct StackFrameForLoadLibraryW
	{
		LPVOID pRetAddr;
		LPWSTR pDllPath;
	};
	StackFrameForLoadLibraryW fakeStackFrame = { reinterpret_cast<LPVOID>(ctx.Eip), remoteBuffer };
	if (::WriteProcessMemory(m_hProcess, reinterpret_cast<LPVOID>(ctx.Esp), &fakeStackFrame, sizeof(fakeStackFrame), nullptr) == 0)
		return InjectionResult::Error_StackFrameNotWritten;

	// manipulate EIP to fake a function call
	DynamicCall<decltype(LoadLibraryW)> funcLoadLibraryW(L"kernel32", "LoadLibraryW");
	ctx.ContextFlags = CONTEXT_CONTROL;
	ctx.Eip = reinterpret_cast<DWORD>(funcLoadLibraryW.GetAddress());
	if (::SetThreadContext(m_hThread, &ctx) == FALSE)
		return InjectionResult::Error_ContextNotSet;

	return InjectionResult::Succeeded;
}



}  // namespace gan
