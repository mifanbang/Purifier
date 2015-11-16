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

#pragma once

#include <windows.h>


// ---------------------------------------------------------------------------
// class InlineHooking32 - inline-hooking Win32 APIs
// ---------------------------------------------------------------------------

class InlineHooking32
{
public:
	template <typename F>
	InlineHooking32(const F* oriFunc, const F* hookFunc)
		: m_state(kNotHooked)
		, m_funcOri((DWORD)oriFunc)
		, m_funcHook((DWORD)hookFunc)
	{
	}

	bool Hook();
	bool Unhook();

private:
	enum HookingState {
		kNotHooked,
		kHooked
	};

	HookingState m_state;
	DWORD m_funcOri;
	DWORD m_funcHook;
};


// ---------------------------------------------------------------------------
// CallTrampoline<>() - trampoline function for Win32 APIs generated at
//                      compile time
// ---------------------------------------------------------------------------

template <typename F, typename... Args>
__declspec(naked) static void WINAPI CallTrampoline32(const F* func, Args... args)
{
	// 1. removing the additional parameter "func" from the stack
	// 2. prolog of original function
	// 3. long jump
	__asm {
		mov eax, [esp+4]	// =func
		add eax, 5			// skips the "jmp" instruction

		push ebx
		mov ebx, [esp+4]	// ret addr
		mov [esp+8], ebx	// overwrites "func" on stack
		pop ebx
		add esp, 4			// now "func" is completely removed from stack

		// Win32 API prolog
		push ebp
		mov ebp, esp

		// long jump
		push eax
		ret
	}  // things below will not get executed

	(*func)(args...);  // enforces type check on parameters
}
