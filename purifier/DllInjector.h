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

#pragma once

#include <string>

#include <windows.h>



// ---------------------------------------------------------------------------
// class DLLInjector32 - DLL injection by setting context
// ---------------------------------------------------------------------------

class DLLInjector32
{
public:
	enum class InjectionResult
	{
		Succeeded,
		Error_DLLPathNotWritten,
		Error_StackFrameNotWritten,
		Error_ContextNotSet
	};


	DLLInjector32(HANDLE hProcess, HANDLE hThread);

	~DLLInjector32();

	InjectionResult Inject(LPCWSTR pDllPath);

private:
	HANDLE m_hProcess;
	HANDLE m_hThread;
	std::wstring m_dllPath;
};
