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

#include <gandr/DebugSession.h>



// ---------------------------------------------------------------------------
// class DllPreloadDebugSession - A DebugSession implementation that preloads a DLL at entry point
// ---------------------------------------------------------------------------

class DLLPreloadDebugSession : public gan::DebugSession
{
public:
	DLLPreloadDebugSession(const CreateProcessParam& newProcParam, const wchar_t* pPayloadPath);

	virtual void OnPreEvent(const PreEvent& event) override;

	virtual ContinueStatus OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO& procInfo) override;

	virtual ContinueStatus OnExceptionTriggered(const EXCEPTION_DEBUG_INFO& exceptionInfo) override;


private:
	HANDLE m_hMainThread;
	std::wstring m_payloadPath;
};
