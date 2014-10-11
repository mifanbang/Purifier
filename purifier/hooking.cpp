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


// ---------------------------------------------------------------------------
// TrampolineManager
// ---------------------------------------------------------------------------

TrampolineManager::TrampolineManager()
	: m_map()
	, m_bank()
	, m_numTramp(0)
{
}


TrampolineManager::~TrampolineManager()
{
	for (auto itr : m_bank)
		VirtualFree((LPVOID)itr, 0, MEM_RELEASE);
}


LPVOID TrampolineManager::AddTrampoline(const Trampoline& tramp)
{
	unsigned int idxBank = m_numTramp / k_numTrampsPerPage;
	unsigned int idxPage = m_numTramp % k_numTrampsPerPage;

	if ((int)idxBank > (int)m_bank.size() - 1) {
		TrampolinePage* newPage = (TrampolinePage*) VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (newPage == NULL)
			return NULL;
		m_bank.push_back(newPage);
	}
	m_bank[idxBank]->trams[idxPage] = tramp;
	m_map[tramp.targetAddr] = m_numTramp;
	m_numTramp++;

	return (LPVOID)&m_bank[idxBank]->trams[idxPage];
}


LPVOID TrampolineManager::GetTrampolineTo(DWORD addr)
{
	static TrampolineManager instance;

	auto mapItr = instance.m_map.find(addr);
	if (mapItr != instance.m_map.end()) {
		unsigned int idx = mapItr->second;
		return (LPVOID) &instance.m_bank[idx / k_numTrampsPerPage]->trams[idx % k_numTrampsPerPage];
	}
	else {
		Trampoline trampoline(addr);
		return instance.AddTrampoline(trampoline);
	}
}


// ---------------------------------------------------------------------------
// TrampolineManager::Trampoline
// ---------------------------------------------------------------------------

TrampolineManager::Trampoline::Trampoline(DWORD addr)
{
	opcodePreamble[0] = 0x55;  // push ebp
	opcodePreamble[1] = 0x8B;
	opcodePreamble[2] = 0xEC;  // mov ebp, esp

	opcodePush = 0x68;
	targetAddr = addr;  // push $addr

	opcodeRet = 0xC3;  // ret
}


TrampolineManager::Trampoline::Trampoline()
{
}
