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

#include <algorithm>
#include <array>

#include <windows.h>

#include "hooking.h"



namespace gan {


// ---------------------------------------------------------------------------
// Prolog32
// ---------------------------------------------------------------------------

bool Prolog32::operator == (const Prolog32& other) const
{
	return memcmp(bytes, other.bytes, sizeof(bytes)) == 0;
}



// ---------------------------------------------------------------------------
// InlineHooking32
// ---------------------------------------------------------------------------

bool InlineHooking32::IsPrologSupported(const Prolog32& prolog)
{
	const std::array<Prolog32, 2> supportedProlog = { {
		{ 0x8B, 0xFF, 0x55, 0x8B, 0xEC },
		{ 0xEB, 0x05, 0x90, 0x90, 0x90 }
	} };

	return std::find(supportedProlog.begin(), supportedProlog.end(), prolog) != supportedProlog.end();
}


InlineHooking32::HookResult InlineHooking32::Hook()
{
	if (m_state != HookState::NotHooked)
		return HookResult::Hooked;

	// check Win32 API prolog
	m_origProlog = *reinterpret_cast<const Prolog32*>(m_funcOri);
	if (!IsPrologSupported(m_origProlog))
		return HookResult::PrologNotSupported;

	// generate a 5-byte long jmp instruction
	BYTE opcodeJmp[5] = {0xE9, 0, 0, 0, 0};  // unconditional jump
	DWORD dwAddrDiff = reinterpret_cast<DWORD>(m_funcHook) - (reinterpret_cast<DWORD>(m_funcOri) + sizeof(opcodeJmp));
	*reinterpret_cast<DWORD*>(opcodeJmp + 1) = dwAddrDiff;

	// make the page writable and overwrite
	DWORD dwOldProtect = 0;
	if (VirtualProtect(m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return HookResult::AccessDenied;
	memcpy(m_funcOri, opcodeJmp, sizeof(opcodeJmp));

	m_state = HookState::Hooked;
	return HookResult::Hooked;
}


InlineHooking32::HookResult InlineHooking32::Unhook()
{
	if (m_state != HookState::Hooked)
		return HookResult::Unhooked;

	const BYTE opcodeProlog[5] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};  // Win32 API prolog

	// makes the page writable and overwrites
	DWORD dwOldProtect = 0;
	if (VirtualProtect(m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return HookResult::AccessDenied;
	memcpy(m_funcOri, opcodeProlog, sizeof(opcodeProlog));

	m_state = HookState::NotHooked;
	return HookResult::Unhooked;
}



}  // namespace gan
