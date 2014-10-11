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

#pragma once


#include <windows.h>

#include <map>
#include <vector>


// ---------------------------------------------------------------------------
// class InlineHooking32 - inline-hooking Win32 APIs
// ---------------------------------------------------------------------------

class InlineHooking32
{
public:
	template <typename F>
	InlineHooking32(const F* oriFunc, const F* hookFunc)
		: m_funcOri((DWORD)oriFunc)
		, m_funcHook((DWORD)hookFunc)
	{
	}

	bool Hook() const;
	bool Unhook() const;

private:
	DWORD m_funcOri;
	DWORD m_funcHook;
};


// ---------------------------------------------------------------------------
// CallTrampoline<>() - trampoline function generated at compile time
// ---------------------------------------------------------------------------

template <typename F, typename... Args>
__declspec(naked) static void WINAPI CallTrampoline(const F* func, Args... args)
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
	}  // things below will not get called

	(*func)(args...);  // enforces type check on parameters
}


// ---------------------------------------------------------------------------
// class TrampolineManager - allocating trampolines at run time to invoke original
//                           functions hooked by class InlineHooking32
// ---------------------------------------------------------------------------

class TrampolineManager
{
public:
	static LPVOID GetTrampolineTo(DWORD addr);

private:
	struct TrampolinePage;

	struct Trampoline
	{
		BYTE opcodePreamble[3];
		BYTE opcodePush;
		DWORD targetAddr;
		BYTE opcodeRet;

		Trampoline(DWORD addr);

	private:
		friend struct TrampolinePage;
		Trampoline();
	};

	// 4096(=page size) / 9 (=sizeof Trampoline) = 455
	static const unsigned int k_numTrampsPerPage = 4096 / sizeof(Trampoline);

	struct TrampolinePage
	{
		Trampoline trams[k_numTrampsPerPage];
	};


	TrampolineManager();
	~TrampolineManager();

	LPVOID AddTrampoline(const Trampoline& tramp);

	std::map<DWORD, unsigned int> m_map;
	std::vector<TrampolinePage*> m_bank;
	unsigned int m_numTramp;
};
