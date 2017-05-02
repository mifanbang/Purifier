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

#include "DebugSession.h"



namespace gan {



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



}  // namespace gan
