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

#include <gandr/hooking.h>

#include "purifier.h"
#include "util.h"
#include "ole32.h"


namespace detour {



static void PrintClsid(REFCLSID clsid)
{
	LPOLESTR progId = nullptr;
	ProgIDFromCLSID(clsid, &progId);

	DEBUG_MSG(L"CLSID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X ProgID:%s\n",
		clsid.Data1,
		clsid.Data2,
		clsid.Data3,
		clsid.Data4[0], clsid.Data4[1], clsid.Data4[2], clsid.Data4[3], clsid.Data4[4], clsid.Data4[5], clsid.Data4[6], clsid.Data4[7],
		progId
	);

	if (progId != nullptr)
		CoTaskMemFree(progId);
}



HRESULT WINAPI CoCreateInstance(
	_In_  REFCLSID  rclsid,
	_In_  LPUNKNOWN pUnkOuter,
	_In_  DWORD     dwClsContext,
	_In_  REFIID    riid,
	_Out_ LPVOID    *ppv
)
{
	const IID iidSkypeBrowser = { 0x3FCB7074, 0xEC9E, 0x4AAF, { 0x9B, 0xE3, 0xC0, 0xE3, 0x56, 0x94, 0x23, 0x66 } };
	const IID iidIOleObject = { 0x00000112, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

	if (memcmp(&iidSkypeBrowser, &rclsid, sizeof(rclsid)) == 0) {
		wchar_t pathPayload[MAX_PATH];
		GetModuleFileName(GetModuleHandle(L""), pathPayload, MAX_PATH);
		CreatePurifiedProcess(GetBrowserHostPath().c_str(), L"-Embedding", GetPayloadPath().c_str());
	}

	DWORD dwResult = NULL;
	gan::CallTrampoline32(::CoCreateInstance, gan::RefArg<IID>(&rclsid), pUnkOuter, dwClsContext, gan::RefArg<IID>(&riid), ppv);
	__asm mov dwResult, eax

	return static_cast<HRESULT>(dwResult);
}



}  // detour
