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

#include "hooking.h"



// ---------------------------------------------------------------------------
// InlineHooking32
// ---------------------------------------------------------------------------

InlineHooking32::HookResult InlineHooking32::Hook()
{
	if (m_state != kNotHooked)
		return HookResult::Hooked;

	// checks presence of Win32 API prolog
	const BYTE opcodeProlog[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};  // Win32 API prolog
	HMODULE hModNtDll = GetModuleHandle(L"ntdll");
	if (hModNtDll == NULL)
		return HookResult::APIError;
	FARPROC pRtlCompareMemory = GetProcAddress(hModNtDll, "RtlCompareMemory");  // hack: using GetProcAddress works around Avira's false positive
	if (pRtlCompareMemory == nullptr)
		return HookResult::APIError;
	auto funcRtlCompareMemory = reinterpret_cast<decltype(&RtlCompareMemory)>(pRtlCompareMemory);
	if (funcRtlCompareMemory(opcodeProlog, m_funcOri, sizeof(opcodeProlog)) != sizeof(opcodeProlog))
		return HookResult::PrologMismatched;

	// generate a 5-byte long jmp instruction
	BYTE opcodeJmp[5] = {0xE9, 0, 0, 0, 0};  // unconditional jump
	DWORD dwAddrDiff = reinterpret_cast<DWORD>(m_funcHook) - (reinterpret_cast<DWORD>(m_funcOri) + sizeof(opcodeJmp));
	*reinterpret_cast<DWORD*>(opcodeJmp + 1) = dwAddrDiff;

	// makes the page writable and overwrites
	DWORD dwOldProtect = 0;
	if (VirtualProtect(m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return HookResult::AccessDenied;
	memcpy(m_funcOri, opcodeJmp, sizeof(opcodeJmp));

	m_state = kHooked;
	return HookResult::Hooked;
}


InlineHooking32::HookResult InlineHooking32::Unhook()
{
	if (m_state != kHooked)
		return HookResult::Unhooked;

	const BYTE opcodeProlog[5] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};  // Win32 API prolog

	// makes the page writable and overwrites
	DWORD dwOldProtect = 0;
	if (VirtualProtect(m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return HookResult::AccessDenied;
	memcpy(m_funcOri, opcodeProlog, sizeof(opcodeProlog));

	m_state = kNotHooked;
	return HookResult::Unhooked;
}