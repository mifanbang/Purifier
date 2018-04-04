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

#include <gandr/Breakpoint.h>
#include <gandr/DllInjector.h>

#include "purifier.h"
#include "util.h"
#include "DllPreloadDebugSession.h"



DLLPreloadDebugSession::DLLPreloadDebugSession(const CreateProcessParam& newProcParam, const wchar_t* pPayloadPath)
	: DebugSession(newProcParam)
	, m_hMainThread(INVALID_HANDLE_VALUE)
	, m_payloadPath(pPayloadPath)
{
}


void DLLPreloadDebugSession::OnPreEvent(const PreEvent& event)
{
	DEBUG_MSG(L"Event: 0x%x\n", event.eventCode);
}


gan::DebugSession::ContinueStatus DLLPreloadDebugSession::OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO& procInfo)
{
	m_hMainThread = procInfo.hThread;

	// install a hardware breakpoint at entry point
	gan::HWBreakpoint32::Enable(m_hMainThread, procInfo.lpStartAddress, 0);

	return ContinueStatus::ContinueThread;
}


gan::DebugSession::ContinueStatus DLLPreloadDebugSession::OnExceptionTriggered(const EXCEPTION_DEBUG_INFO& exceptionInfo)
{
	switch (exceptionInfo.ExceptionRecord.ExceptionCode) {
		case EXCEPTION_SINGLE_STEP:  // hardware breakpoint triggered
		{
			// uninstall the hardware breakpoint at entry point
			gan::HWBreakpoint32::Disable(m_hMainThread, 0);

			gan::DLLInjectorByContext32 injector(GetHandle(), m_hMainThread);
			injector.Inject(m_payloadPath.c_str());

			return ContinueStatus::CloseSession;
		}

		case EXCEPTION_BREAKPOINT:  // expecting the breakpoint triggered by Windows Debug API for attaching the process
		{
			// do nothing
			break;
		}

		default:
		{
			return ContinueStatus::NotHandled;  // forward if exception is other than a breakpoint
		}
	}

	return ContinueStatus::ContinueThread;
}
