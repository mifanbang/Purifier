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

#include <string>
#include <vector>



// forward declaration
struct tagPROCESSENTRY32W;  // in tlhelp32.h



namespace gan {



struct ProcessInfo
{
	uint32_t pid;
	uint32_t nThread;
	uint32_t pidParent;
	uint32_t basePriority;
	std::wstring path;

	ProcessInfo(const struct ::tagPROCESSENTRY32W& procEntry) noexcept;
};


using ProcessList = std::vector<ProcessInfo>;



// ---------------------------------------------------------------------------
// class ProcessEnumerator32 - process list snapshot taker
// ---------------------------------------------------------------------------

class ProcessEnumerator32
{
public:
	enum class EnumResult
	{
		Success,
		SnapshotFailed,
		Process32Failed,
	};


	ProcessEnumerator32() noexcept;

	EnumResult Enumerate() noexcept;  // result is cached
	void GetProcessList(ProcessList& out) const;


private:
	ProcessList m_cache;
};



}  // namespace gan
