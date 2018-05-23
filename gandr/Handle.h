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



class AutoHandle
{
public:
	AutoHandle(HANDLE handle)
		: m_handle(handle)
	{ }
	~AutoHandle()
	{
		if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE)
			::CloseHandle(m_handle);
	}

	// non-copyable
	AutoHandle(const AutoHandle&) = delete;
	AutoHandle& operator=(const AutoHandle&) = delete;

	// movable
	AutoHandle(AutoHandle&& other)
		: m_handle(other.m_handle)
	{
		other.m_handle = nullptr;
	}
	AutoHandle& operator=(AutoHandle&& other)
	{
		m_handle = other.m_handle;
		other.m_handle = nullptr;
	}


	operator HANDLE() const
	{
		return m_handle;
	}

private:
	HANDLE m_handle;
};



}  // namespace gan
