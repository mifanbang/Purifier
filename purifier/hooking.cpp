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

#include "hooking.h"



// ---------------------------------------------------------------------------
// InlineHooking32
// ---------------------------------------------------------------------------

bool InlineHooking32::Hook()
{
	if (m_state != kNotHooked)
		return false;

	// checks presence of Win32 API prolog
	const BYTE opcodeProlog[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};  // Win32 API prolog
	FARPROC pRtlCompareMemory = GetProcAddress(GetModuleHandle(L"ntdll"), "RtlCompareMemory");  // hack: using GetProcAddress works around Avira's false positive
	if (pRtlCompareMemory == nullptr)
		return false;
	auto funcRtlCompareMemory = reinterpret_cast<decltype(&RtlCompareMemory)>(pRtlCompareMemory);
	if (funcRtlCompareMemory(opcodeProlog, (void*)m_funcOri, sizeof(opcodeProlog)) != sizeof(opcodeProlog))
		return false;

	// generate a 5-byte long jmp instruction
	BYTE opcodeJmp[5] = {0xE9, 0, 0, 0, 0};  // unconditional jump
	DWORD dwAddrDiff = (DWORD)m_funcHook - ((DWORD)m_funcOri + sizeof(opcodeJmp));
	*reinterpret_cast<DWORD*>(opcodeJmp + 1) = dwAddrDiff;

	// makes the page writable and overwrites
	DWORD dwOldProtect = 0;
	if (VirtualProtect((LPVOID)m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return false;
	memcpy((LPVOID)m_funcOri, opcodeJmp, sizeof(opcodeJmp));

	m_state = kHooked;
	return true;
}


bool InlineHooking32::Unhook()
{
	if (m_state != kHooked)
		return false;

	const BYTE opcodeProlog[5] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};  // Win32 API prolog

	// makes the page writable and overwrites
	DWORD dwOldProtect = 0;
	if (VirtualProtect((LPVOID)m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return false;
	memcpy((LPVOID)m_funcOri, opcodeProlog, sizeof(opcodeProlog));

	m_state = kNotHooked;
	return true;
}
