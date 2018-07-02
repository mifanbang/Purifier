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

#include "Buffer.h"

#include <cstring>

#include <windows.h>



namespace {



size_t GetProperCapacity(size_t requestedSize) noexcept
{
	constexpr size_t maxSize = static_cast<size_t>(-1);
	constexpr size_t mostSigBit = ~(maxSize / 2);

	if (requestedSize < static_cast<size_t>(gan::Buffer::k_minSize))
		return gan::Buffer::k_minSize;
	else if ((requestedSize & mostSigBit) != 0)  // prevent the left-shift below from overflowing
		return mostSigBit;

	size_t capacity = 1;
	for (; requestedSize > 0; requestedSize = requestedSize >> 1)
		capacity = capacity << 1;

	return capacity;
}



}  // unnamed namespace



namespace gan {



std::unique_ptr<Buffer> Buffer::Allocate(size_t size) noexcept
{
	auto capacity = GetProperCapacity(size);
	if (capacity >= size) {
		auto* dataPtr = reinterpret_cast<uint8_t*>(::HeapAlloc(GetProcessHeap(), 0, capacity));
		if (dataPtr != nullptr)
			return std::unique_ptr<Buffer>(new Buffer(capacity, size, dataPtr));
	}

	return std::unique_ptr<Buffer>();
}


Buffer::Buffer(size_t capacity, size_t size, uint8_t* addr) noexcept
	: m_capacity(capacity)
	, m_size(size)
	, m_data(addr)
{
}


Buffer::~Buffer()
{
	::HeapFree(GetProcessHeap(), 0, m_data);
}


bool Buffer::Resize(size_t newSize) noexcept
{
	if (newSize <= m_capacity)
		return true;

	// need a bigger memory block
	auto newCapacity = GetProperCapacity(newSize);
	if (newCapacity < newSize)
		return false;

	auto* newAddr = reinterpret_cast<uint8_t*>(::HeapReAlloc(::GetProcessHeap(), 0, m_data, newCapacity));
	if (newAddr != nullptr) {
		m_capacity = newCapacity;
		m_size = newSize;
		m_data = newAddr;

		return true;
	}

	return false;
}


}  // namespace gan
