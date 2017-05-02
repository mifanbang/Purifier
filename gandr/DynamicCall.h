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

#include <windows.h>



// ---------------------------------------------------------------------------
// class DynamicCall32 - dynamically calling a Win32 API function
// ---------------------------------------------------------------------------

template <typename T>
class DynamicCall32
{
public:
	DynamicCall32(const wchar_t* nameLib, const char* nameFunc)
		: m_pFunc(nullptr)
	{
		m_pFunc = reinterpret_cast<T*>(GetProcAddress(GetModuleHandle(nameLib), nameFunc));
	}

	bool IsValid() const
	{
		return m_pFunc != nullptr;
	}

	T* GetAddress() const
	{
		return m_pFunc;
	}

	template <typename... Arg>
	auto operator () (Arg&&... arg) const
	{
		return m_pFunc(std::forward<Arg>(arg)...);
	}


private:
	T* m_pFunc;
};
