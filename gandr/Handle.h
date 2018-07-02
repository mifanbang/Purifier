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



template <typename TypeHandle, typename FuncDeleter>
class AutoHandle
{
public:
	AutoHandle(TypeHandle handle, FuncDeleter& deleter)
		: m_handle(handle)
		, m_deleter(deleter)
	{ }
	AutoHandle(TypeHandle handle, FuncDeleter&& deleter)
		: m_handle(handle)
		, m_deleter(deleter)
	{ }

	~AutoHandle()
	{
		m_deleter(m_handle);
	}

	inline operator TypeHandle() const	{ return m_handle; }
	inline TypeHandle& GetRef()			{ return m_handle; }

	// non-copyable and inherently non-movable
	AutoHandle(const AutoHandle&) = delete;
	AutoHandle& operator=(const AutoHandle&) = delete;


private:
	FuncDeleter& m_deleter;
	TypeHandle m_handle;
};


class AutoWinHandle : public AutoHandle<HANDLE, decltype(::CloseHandle)>
{
	using super = AutoHandle<HANDLE, decltype(::CloseHandle)>;

public:
	AutoWinHandle(HANDLE handle) noexcept
		: super(handle, ::CloseHandle)
	{ }

	// movable because calling ::CloseHandle(nullptr) is safe
	inline AutoWinHandle(AutoWinHandle&& other) noexcept
		: super(other.GetRef(), ::CloseHandle)
	{
		other.GetRef() = nullptr;
	}
	inline AutoWinHandle& operator=(AutoWinHandle&& other) noexcept
	{
		GetRef() = other.GetRef();
		other.GetRef() = nullptr;
	}
};



}  // namespace gan
