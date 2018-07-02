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

#include <cstdint>
#include <memory>


namespace gan {



class Buffer
{
public:
	static const uint32_t k_minSize = 128;  // 128 B

	// factory function
	static std::unique_ptr<Buffer> Allocate(size_t size) noexcept;

	~Buffer();

	// non-copyable & non-movable
	Buffer(const Buffer& other) = delete;
	Buffer(Buffer&& other) = delete;
	Buffer& operator=(const Buffer& other) = delete;
	Buffer& operator=(Buffer&& other) = delete;

	operator const uint8_t*() const noexcept	{ return m_data; }
	operator uint8_t*() noexcept				{ return m_data; }
	const uint8_t* GetData() const noexcept		{ return m_data; }
	uint8_t* GetData() noexcept					{ return m_data; }

	inline size_t GetSize() const noexcept		{ return m_size; }
	bool Resize(size_t newSize) noexcept;


private:
	Buffer(size_t capacity, size_t size, uint8_t* addr) noexcept;


	size_t m_capacity;
	size_t m_size;  // size in use
	uint8_t* m_data;
};



}  // namespace gan
