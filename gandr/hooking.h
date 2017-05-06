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

#pragma once

#include <cstdint>


namespace gan {



struct Prolog32
{
	uint8_t bytes[5];

	bool operator == (const Prolog32& other) const;
};



// ---------------------------------------------------------------------------
// class InlineHooking32 - inline-hooking Win32 APIs
// ---------------------------------------------------------------------------

class InlineHooking32
{
public:
	enum class HookResult
	{
		Hooked,
		APIError,
		PrologNotSupported,
		AccessDenied,
		Unhooked
	};


	template <typename F>
	InlineHooking32(const F* oriFunc, const F* hookFunc)
		: m_state(HookState::NotHooked)
		, m_funcOri(oriFunc)
		, m_funcHook(hookFunc)
		, m_origProlog()
	{
	}


	static bool IsPrologSupported(const Prolog32& prolog);

	HookResult Hook();
	HookResult Unhook();


private:
	enum class HookState
	{
		NotHooked,
		Hooked
	};

	HookState m_state;
	void* m_funcOri;
	void* m_funcHook;
	Prolog32 m_origProlog;
};



// ---------------------------------------------------------------------------
// CallTrampoline<>() - trampoline function for Win32 APIs generated at
//                      compile time
// ---------------------------------------------------------------------------

template <typename F>
__declspec(naked) static void __stdcall CallTrampoline32(const F* func)
{
	// 1. removing the additional parameter "func" from the stack
	// 2. long jump
	__asm {
		mov eax, [esp+4]	// =func
		add eax, 5			// skips the "jmp" instruction

		push ebx
		mov ebx, [esp+4]	// ret addr
		mov [esp+8], ebx	// overwrites "func" on stack
		pop ebx
		add esp, 4			// now "func" is completely removed from stack

		// long jump
		push eax
		ret
	}  // things below will not get executed
}


template <typename F, typename... Args>
__declspec(naked) static void __stdcall CallTrampoline32(const F* func, Args... args)
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



// ---------------------------------------------------------------------------
// class RefArg<> - for any parameter to the F of CallTrampoline32<F, ...>() being
//                  a reference, use this class to wrap its pointer form
// ---------------------------------------------------------------------------

template <typename T>
class RefArg
{
public:
	RefArg(const T* ptr)
		: m_ptr(ptr)
	{ }

	operator const T& () const { return *m_ptr; }

private:
	const T* m_ptr;
};



}  // namespace gan
