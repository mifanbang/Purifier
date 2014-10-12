/*
 *  purifier - removing ad banners in Microsoft Skype
 *  Copyright (C) 2011-2014 Mifan Bang <http://debug.tw>.
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

bool InlineHooking32::Hook() const
{
	DWORD dwAddrDiff = (DWORD)m_funcHook - (DWORD)m_funcOri - 5;  // an unconditional jump is 5-byte long
	BYTE opcodes[5] = {0xE9, 0, 0, 0, 0};  // unconditional jump
	*reinterpret_cast<DWORD*>(opcodes + 1) = dwAddrDiff;

	DWORD dwOldProtect = 0;
	if (VirtualProtect((LPVOID)m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return false;
	memcpy((LPVOID)m_funcOri, opcodes, sizeof(opcodes));

	return true;
}


bool InlineHooking32::Unhook() const
{
	BYTE opcodes[5] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};  // Win32 API preamble
	DWORD dwOldProtect = 0;
	if (VirtualProtect((LPVOID)m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return false;
	memcpy((LPVOID)m_funcOri, opcodes, sizeof(opcodes));

	return true;
}
