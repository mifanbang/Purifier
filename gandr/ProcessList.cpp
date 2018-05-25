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

#include "ProcessList.h"

#include <windows.h>
#include <tlhelp32.h>  // must be included after windows.h, which sucks

#include "Handle.h"



namespace gan {



ProcessInfo::ProcessInfo(const ::tagPROCESSENTRY32W& procEntry)
	: pid(procEntry.th32ProcessID)
	, nThread(procEntry.cntThreads)
	, pidParent(procEntry.th32ParentProcessID)
	, basePriority(procEntry.pcPriClassBase)
	, path(procEntry.szExeFile)
{
}



ProcessEnumerator32::ProcessEnumerator32()
	: m_cache()
{
	Enumerate();
}


ProcessEnumerator32::EnumResult ProcessEnumerator32::Enumerate()
{
	AutoWinHandle hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return EnumResult::SnapshotFailed;

	ProcessList newProcList;
	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);
	BOOL proc32Result = ::Process32FirstW(hSnap, &procEntry);

	while (proc32Result == TRUE) {
		newProcList.emplace_back(procEntry);
		proc32Result = ::Process32NextW(hSnap, &procEntry);
	}

	// Process32Next() ends with returning FALSE and setting error code to ERROR_NO_MORE_FILES
	if (proc32Result == FALSE && ::GetLastError() != ERROR_NO_MORE_FILES)
		return EnumResult::Process32Failed;

	m_cache = newProcList;
	return EnumResult::Success;
}


void ProcessEnumerator32::GetProcessList(ProcessList& out) const
{
	out = m_cache;
}



}  // namespace gan
