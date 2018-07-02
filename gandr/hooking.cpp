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

#include "hooking.h"

#include <algorithm>
#include <array>
#include <unordered_map>

#include <windows.h>

#include "Mutex.h"



namespace {



template <gan::PrologType32 type>
__declspec(naked) void __stdcall Trampoline32() noexcept;

template <>
__declspec(naked) void __stdcall Trampoline32<gan::PrologType32::Standard>() noexcept
{
	__asm {
		// Win32 API prolog
		push ebp
		mov ebp, esp

		// long jump
		push ecx
		ret
	}
}

template <>
__declspec(naked) void __stdcall Trampoline32<gan::PrologType32::NoLocalStack>() noexcept
{
	__asm {
		// long jump
		push ecx
		ret
	}
}



}  // unnamed namespace



namespace gan {



// ---------------------------------------------------------------------------
// Prolog32
// ---------------------------------------------------------------------------

bool Prolog32::operator==(const Prolog32& other) const noexcept
{
	return memcmp(bytes, other.bytes, sizeof(bytes)) == 0;
}



// ---------------------------------------------------------------------------
// SupportedProlog
// ---------------------------------------------------------------------------

// must be the same order as definition of PrologType32
const SupportedProlog::PrologSupportList SupportedProlog::s_supportedPrologs = { {
	{ { 0x8B, 0xFF, 0x55, 0x8B, 0xEC }, PrologType32::Standard },
	{ { 0xEB, 0x05, 0x90, 0x90, 0x90 }, PrologType32::NoLocalStack },
	{ { 0x00, 0x00, 0x00, 0x00, 0x00 }, PrologType32::NotSupported }
} };


const Prolog32& SupportedProlog::GetProlog(PrologType32 type) noexcept
{
	return s_supportedPrologs[static_cast<size_t>(type)].first;
}


PrologType32 SupportedProlog::GetType(const Prolog32& prolog) noexcept
{
	auto itr = std::find_if(s_supportedPrologs.cbegin(), s_supportedPrologs.cend(), [&target = prolog] (const auto& item) {
		return item.first == target;
	} );
	return itr != s_supportedPrologs.cend() ? itr->second : PrologType32::NotSupported;
}


void* SupportedProlog::GetTrampoline(PrologType32 type) noexcept
{
	switch (type) {
		case PrologType32::Standard:
			return Trampoline32<PrologType32::Standard>;

		case PrologType32::NoLocalStack:
			return Trampoline32<PrologType32::NoLocalStack>;

		default:
			return nullptr;
	}
}



// ---------------------------------------------------------------------------
// PrologTable32
// ---------------------------------------------------------------------------

using PrologTableData32 = std::unordered_map<const void*, PrologType32>;
static ThreadSafeResource<PrologTableData32> s_prologTableData;


PrologType32 PrologTable32::Query(const void* func) noexcept
{
	return s_prologTableData.ApplyOperation( [func] (const PrologTableData32& data) -> auto {
		auto itr = data.find(func);

		if (itr == data.end()) {
			const Prolog32& prolog = *reinterpret_cast<const Prolog32*>(func);
			auto type = SupportedProlog::GetType(prolog);
			Register(func, type);
			return type;
		}

		return itr->second;
	} );
}


bool PrologTable32::Register(const void* func, PrologType32 type) noexcept
{
	return s_prologTableData.ApplyOperation( [func, type] (PrologTableData32& data) -> bool {
		auto itr = data.find(func);
		if (itr != data.end())
			return false;

		data[func] = type;
		return true;
	} );
}



// ---------------------------------------------------------------------------
// InlineHooking32
// ---------------------------------------------------------------------------

InlineHooking32::HookResult InlineHooking32::Hook() noexcept
{
	if (m_state != HookState::NotHooked)
		return HookResult::Hooked;

	// other hooks is on the target address
	if (PrologTable32::Query(m_funcOri) == PrologType32::NotSupported)
		return HookResult::PrologNotSupported;

	// check Win32 API prolog
	const Prolog32& prolog = *reinterpret_cast<const Prolog32*>(m_funcOri);
	m_prologType = SupportedProlog::GetType(prolog);
	if (m_prologType == PrologType32::NotSupported)
		return HookResult::AddressRegistered;

	// generate a 5-byte long jmp instruction
	BYTE opcodeJmp[5] = {0xE9, 0, 0, 0, 0};  // unconditional jump
	DWORD dwAddrDiff = reinterpret_cast<DWORD>(m_funcHook) - (reinterpret_cast<DWORD>(m_funcOri) + sizeof(opcodeJmp));
	*reinterpret_cast<DWORD*>(opcodeJmp + 1) = dwAddrDiff;

	// make the page writable and overwrite
	DWORD dwOldProtect = 0;
	if (VirtualProtect(m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return HookResult::AccessDenied;
	CopyMemory(m_funcOri, opcodeJmp, sizeof(opcodeJmp));

	m_state = HookState::Hooked;
	return HookResult::Hooked;
}


InlineHooking32::HookResult InlineHooking32::Unhook() noexcept
{
	if (m_state != HookState::Hooked)
		return HookResult::Unhooked;

	auto type = PrologTable32::Query(m_funcOri);
	if (type == PrologType32::NotSupported)
		return HookResult::PrologNotSupported;  // very strange. but safety first.
	auto prolog = SupportedProlog::GetProlog(type);

	// makes the page writable and overwrites
	DWORD dwOldProtect = 0;
	if (VirtualProtect(m_funcOri, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return HookResult::AccessDenied;
	CopyMemory(m_funcOri, prolog.bytes, sizeof(prolog.bytes));

	m_state = HookState::NotHooked;
	return HookResult::Unhooked;
}



}  // namespace gan
