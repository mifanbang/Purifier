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

#pragma once

#include <array>
#include <cstdint>


namespace gan {



// ---------------------------------------------------------------------------
// struct Prolog32 - 32-bit function prolog
// ---------------------------------------------------------------------------

struct Prolog32
{
	uint8_t bytes[5];

	bool operator==(const Prolog32& other) const noexcept;
};



// ---------------------------------------------------------------------------
// enum PrologType32 & class SupportedProlog - helpers for prolog
// ---------------------------------------------------------------------------

enum class PrologType32
{
	Standard,
	NoLocalStack,
	NotSupported
};


class SupportedProlog
{
public:
	static const Prolog32& GetProlog(PrologType32 type) noexcept;
	static PrologType32 GetType(const Prolog32& prolog) noexcept;

	static void* GetTrampoline(PrologType32 type) noexcept;


private:
	using PrologSupportList = std::array<std::pair<Prolog32, PrologType32>, 3>;
	static const PrologSupportList s_supportedPrologs;
};



// ---------------------------------------------------------------------------
// class PrologTable32 - registry for known prologs
// ---------------------------------------------------------------------------

class PrologTable32
{
public:
	static PrologType32 Query(const void* func) noexcept;

private:
	static bool Register(const void* func, PrologType32 type) noexcept;
};



// ---------------------------------------------------------------------------
// class InlineHooking32 - inline hook for hotpatchable stdcall functions
// ---------------------------------------------------------------------------

class InlineHooking32
{
public:
	enum class HookResult
	{
		Hooked,				// success
		AddressRegistered,	// a previous hook existed in PrologTable32
		APIError,			// Win32 API error
		PrologNotSupported,
		AccessDenied,		// failed to write memory
		Unhooked
	};


	template <typename F>
	InlineHooking32(const F* oriFunc, const F* hookFunc) noexcept
		: m_state(HookState::NotHooked)
		, m_funcOri(oriFunc)
		, m_funcHook(hookFunc)
		, m_prologType(PrologType32::NotSupported)
	{
	}


	HookResult Hook() noexcept;
	HookResult Unhook() noexcept;


private:
	enum class HookState
	{
		NotHooked,
		Hooked
	};

	HookState m_state;
	void* m_funcOri;
	void* m_funcHook;
	PrologType32 m_prologType;
};



// ---------------------------------------------------------------------------
// macro CallTram32 - shortcut for calling trampoline (strong-typed, yeah!)
// ---------------------------------------------------------------------------

template <typename T>
struct TrampolineCallGate32;

template <typename R, typename... ArgT>
struct TrampolineCallGate32<R __stdcall (ArgT...)>
{
	using CallType = R(TrampolineCallGate32<R __stdcall (ArgT...)>::*)(ArgT...);

	static CallType ConvertPtr(const void* pointer) noexcept
	{
		CallType result;
		__asm {
			mov eax, pointer
			mov result, eax
		}
		return result;
	}
};

// CallTram32 tricks compiler into generating a __thiscall and storing the targer address into ECX
#define __HELPER_TYPE__(func)	::gan::TrampolineCallGate32<decltype(func)>
#define CallTram32(func)		( *(reinterpret_cast<__HELPER_TYPE__(func)*>(reinterpret_cast<uint8_t*>(func) + sizeof(gan::Prolog32)) ) .* __HELPER_TYPE__(func)::ConvertPtr( ::gan::SupportedProlog::GetTrampoline(::gan::PrologTable32::Query(func)) ) )



}  // namespace gan
