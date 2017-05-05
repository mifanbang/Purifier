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



class Buffer
{
public:
	static const uint32_t k_maxSize = 256 * 1024 * 1024;  // 256 MB
	static const uint32_t k_minSize = 128;  // 128 B


	Buffer(size_t size);
	Buffer(const Buffer& other) = delete;
	Buffer(Buffer&& other) = delete;
	~Buffer();

	const Buffer& operator = (const Buffer& other) = delete;
	Buffer&& operator = (Buffer&& other) = delete;

	operator const uint8_t* () const	{ return m_data; }
	operator uint8_t* ()				{ return m_data; }
	const uint8_t* GetData() const		{ return m_data; }
	uint8_t* GetData()					{ return m_data; }

	size_t GetSize() const	{ return m_size; }
	void Resize(size_t size);


private:
	size_t m_capacity;
	size_t m_size;  // size in use
	uint8_t* m_data;
};



}  // namespace gan
