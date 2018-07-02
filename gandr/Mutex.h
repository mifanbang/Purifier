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

#include <windows.h>



namespace gan {



template <typename T, typename... Arg>
class ThreadSafeResource
{
public:
	ThreadSafeResource(Arg&&... arg) noexcept
		: m_resInst(std::forward<Arg>(arg)...)
	{
		::InitializeCriticalSection(&m_lock);
	}

	~ThreadSafeResource()
	{
		::DeleteCriticalSection(&m_lock);
	}

	template <typename F>
	auto ApplyOperation(const F& func)
	{
		::EnterCriticalSection(&m_lock);
		auto result = func(m_resInst);
		::LeaveCriticalSection(&m_lock);

		return result;
	}


private:
	T m_resInst;
	CRITICAL_SECTION m_lock;
};



}  // namespace gan
