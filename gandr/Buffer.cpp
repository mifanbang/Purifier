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

#include <algorithm>
#include <cstring>

#include "Buffer.h"



namespace gan {



static size_t GetProperCapacity(size_t requestedSize)
{
	if (requestedSize > static_cast<size_t>(Buffer::k_maxSize))
		return Buffer::k_maxSize;
	else if (requestedSize < static_cast<size_t>(Buffer::k_minSize))
		return Buffer::k_minSize;

	size_t capacity = 1;
	for (; requestedSize > 0; requestedSize = requestedSize >> 1)
		capacity = capacity << 1;

	return capacity;
}



static size_t GetProperSize(size_t size)
{
	return std::min(size, static_cast<size_t>(Buffer::k_maxSize));
}



Buffer::Buffer(size_t size)
	: m_capacity(GetProperCapacity(size))
	, m_size(GetProperSize(size))
	, m_data(new uint8_t[m_capacity])
{
}


Buffer::~Buffer()
{
	delete[] m_data;
}


void Buffer::Resize(size_t size)
{
	size_t newSize = GetProperSize(size);
	if (newSize <= m_capacity)
		return;

	// need a bigger memory block
	size_t newCapacity = GetProperCapacity(newSize);
	uint8_t* newData = new uint8_t[newCapacity];
	memcpy(newData, m_data, m_size);

	delete[] m_data;
	m_capacity = newCapacity;
	m_size = newSize;
	m_data = newData;
}


}  // namespace gan
