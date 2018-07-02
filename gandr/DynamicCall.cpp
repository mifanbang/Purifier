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

#include "DynamicCall.h"

#include <algorithm>
#include <memory>
#include <vector>

#include <windows.h>

#include "Mutex.h"



namespace {



class LibraryManager {
public:
	static HMODULE Get(LPCWSTR name) noexcept {
		auto hModule = ::GetModuleHandleW(name);
		if (hModule == nullptr) {
			hModule = ::LoadLibraryW(name);
			if (hModule == nullptr)
				return nullptr;

			// unload library in the future
			s_libUnloadList.ApplyOperation( [hModule](auto& libs) -> auto {
				return libs.emplace_back(hModule);
			} );
		}
		return hModule;
	}

	static bool Unload(LPCWSTR name) noexcept {
		auto hModule = ::GetModuleHandleW(name);
		if (hModule == nullptr)
			return false;
		return Unload(hModule);
	}

	static bool Unload(HMODULE hModule) noexcept {
		return s_libUnloadList.ApplyOperation( [hModule](LibraryUnloadList& libs) -> bool {
			auto itr = std::find(libs.begin(), libs.end(), hModule);
			if (itr == libs.end())
				return false;
			libs.back() = *itr;
			libs.pop_back();
			::FreeLibrary(hModule);
			return true;
		} );
	}


private:
	class LibraryUnloadList : public std::vector<HMODULE>
	{
	public:
		~LibraryUnloadList()
		{
			for (auto& item : *this)
				::FreeLibrary(item);
		}
	};

	static gan::ThreadSafeResource<LibraryUnloadList> s_libUnloadList;
};

gan::ThreadSafeResource<LibraryManager::LibraryUnloadList> LibraryManager::s_libUnloadList;



}  // unnamed namespace



namespace gan {



void* ObtainFunction(const wchar_t* library, const char* func) noexcept
{
	auto hModule = LibraryManager::Get(library);
	if (hModule == nullptr)
		return nullptr;
	return ::GetProcAddress(hModule, func);
}



}  // namespace gan
