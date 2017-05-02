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

#include <windows.h>

#include "Debugger.h"



// ---------------------------------------------------------------------------
// class DebugSession
// ---------------------------------------------------------------------------

DebugSession::DebugSession(const CreateProcessParam& newProcParam)
	: m_pid(0)
	, m_hProc(INVALID_HANDLE_VALUE)
{
	STARTUPINFO si;
	if (newProcParam.startUpInfo != nullptr)
		si = *newProcParam.startUpInfo;
	else
		ZeroMemory(&si, sizeof(si));

	PROCESS_INFORMATION procInfo;
	if (CreateProcessW(newProcParam.imagePath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &procInfo) != 0) {
		m_pid = procInfo.dwProcessId;
		m_hProc = procInfo.hProcess;
	}
}


DebugSession::~DebugSession()
{
	End(EndOption::Kill);
}


void DebugSession::End(EndOption option)
{
	if (IsValid()) {
		DebugActiveProcessStop(m_pid);

		if (option == EndOption::Kill)
			TerminateProcess(m_hProc, 0);

		m_pid = 0;
	}
}


bool DebugSession::IsValid() const
{
	return m_pid != 0;
}



// ---------------------------------------------------------------------------
// class Debugger
// ---------------------------------------------------------------------------

Debugger::Debugger()
	: m_flagEventLoopExit(false)
{
}


Debugger::~Debugger()
{
	RemoveAllSessions(DebugSession::EndOption::Kill);
}


Debugger::EventLoopResult Debugger::EnterEventLoop()
{
	DEBUG_EVENT dbgEvent;

	m_flagEventLoopExit = false;
	while (!m_flagEventLoopExit) {
		if (m_sessions.size() == 0)
			return EventLoopResult::AllDetached;

		DebugSession::ContinueStatus contStatus = DebugSession::ContinueStatus::ContinueThread;  // continue by default

		if (WaitForDebugEvent(&dbgEvent, INFINITE) == 0)
			return EventLoopResult::ErrorOccurred;

		auto itr = m_sessions.find(dbgEvent.dwProcessId);
		if (itr == m_sessions.end())
			continue;  // this shouldn't happen though
		auto pSession = itr->second;

		DebugSession::PreEvent preEvent = {
			dbgEvent.dwDebugEventCode,
			dbgEvent.dwThreadId
		};
		pSession->OnPreEvent(preEvent);

		switch (dbgEvent.dwDebugEventCode) {
			case EXCEPTION_DEBUG_EVENT:
			{
				contStatus = pSession->OnExceptionTriggered(dbgEvent.u.Exception);
				break;
			}
			case CREATE_THREAD_DEBUG_EVENT:
			{
				contStatus = pSession->OnThreadCreated(dbgEvent.u.CreateThread);
				break;
			}
			case CREATE_PROCESS_DEBUG_EVENT:
			{
				contStatus = pSession->OnProcessCreated(dbgEvent.u.CreateProcessInfo);
				CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);
				break;
			}
			case EXIT_THREAD_DEBUG_EVENT:
			{
				contStatus = pSession->OnThreadExited(dbgEvent.u.ExitThread);
				break;
			}
			case EXIT_PROCESS_DEBUG_EVENT:
			{
				contStatus = pSession->OnProcessExited(dbgEvent.u.ExitProcess);
				break;
			}
			case LOAD_DLL_DEBUG_EVENT:
			{
				contStatus = pSession->OnDllLoaded(dbgEvent.u.LoadDll);
				CloseHandle(dbgEvent.u.LoadDll.hFile);
				break;
			}
			case UNLOAD_DLL_DEBUG_EVENT:
			{
				contStatus = pSession->OnDllUnloaded(dbgEvent.u.UnloadDll);
				break;
			}
			case OUTPUT_DEBUG_STRING_EVENT:
			{
				contStatus = pSession->OnStringOutput(dbgEvent.u.DebugString);
				break;
			}
			case RIP_EVENT:
			{
				contStatus = pSession->OnRipEvent(dbgEvent.u.RipInfo);
				break;
			}
			default:
			{
				break;
			}
		}

		ContinueDebugEvent(
			dbgEvent.dwProcessId,
			dbgEvent.dwThreadId,
			contStatus == DebugSession::ContinueStatus::NotHandled ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE
		);

		if (contStatus == DebugSession::ContinueStatus::CloseSession)
			RemoveSession(dbgEvent.dwProcessId, DebugSession::EndOption::Detach);
	}

	return EventLoopResult::ExitRequested;
}


bool Debugger::AddSessionInstance(const std::shared_ptr<DebugSession>& pSession)
{
	if (!pSession->IsValid())
		return false;

	DebugSession::Identifier sessId = pSession->GetId();
	auto itr = m_sessions.find(sessId);
	if (itr != m_sessions.end())
		return false;

	m_sessions.insert(decltype(m_sessions)::value_type(sessId, pSession));
	return true;
}


bool Debugger::RemoveSession(DebugSession::Identifier sessionId, DebugSession::EndOption option)
{
	auto itr = m_sessions.find(sessionId);
	if (itr == m_sessions.end())
		return false;

	itr->second->End(option);
	m_sessions.erase(itr);
	return true;
}


void Debugger::RemoveAllSessions(DebugSession::EndOption option)
{
	for (auto& itr : m_sessions)
		itr.second->End(option);
	m_sessions.clear();
}


void Debugger::GetSessionList(IdList& output) const
{
	output.clear();
	for (auto& itr : m_sessions)
		output.push_back(itr.first);
}
