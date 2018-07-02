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


namespace gan {



// will load library if not loaded before
void* ObtainFunction(const wchar_t* library, const char* func) noexcept;



// ---------------------------------------------------------------------------
// class DynamicCall - dynamically loading and calling a function
// ---------------------------------------------------------------------------

template <typename T>
class DynamicCall
{
public:
	DynamicCall(const wchar_t* library, const char* func) noexcept
		: m_pFunc(nullptr)
	{
		m_pFunc = reinterpret_cast<T*>(ObtainFunction(library, func));
	}

	inline bool IsValid() const noexcept
	{
		return m_pFunc != nullptr;
	}

	inline T* GetAddress() const noexcept
	{
		return m_pFunc;
	}

	template <typename... Arg>
	auto operator()(Arg&&... arg) const
	{
		return m_pFunc(std::forward<Arg>(arg)...);
	}


private:
	T* m_pFunc;
};



}  // namespace gan
