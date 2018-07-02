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

#include <algorithm>
#include <array>
#include <vector>

#include <windows.h>
#include <wininet.h>

#include <gandr/hooking.h>

#include "shared/purifier.h"
#include "shared/util.h"
#include "detours/ole32.h"
#include "detours/user32.h"
#include "detours/wininet.h"



class Scenario
{
public:
	Scenario()
		: m_hookList()
	{ }

	void Start()
	{
		for (auto& hook : m_hookList)
			hook.Hook();
	}

	void Stop()
	{
		for (auto& hook : m_hookList)
			hook.Unhook();
	}

protected:
	std::vector<gan::InlineHooking32> m_hookList;
};


class ScenarioSkype : public Scenario
{
public:
	ScenarioSkype()
		: Scenario()
	{
		m_hookList.emplace_back(HttpOpenRequestW, detour::HttpOpenRequestW);
		m_hookList.emplace_back(CreateWindowExW, detour::CreateWindowExW);
		m_hookList.emplace_back(CoCreateInstance, detour::CoCreateInstance);
	}
};


class ScenarioBrowserHost : public Scenario
{
public:
	ScenarioBrowserHost()
		: Scenario()
	{
		m_hookList.emplace_back(HttpOpenRequestW, detour::HttpOpenRequestW);
		m_hookList.emplace_back(CoResumeClassObjects, detour::CoResumeClassObjects);
	}
};


// factory
Scenario* CreateScenario()
{
	if (::GetModuleHandleW(L"SkypeBrowserHost.exe") != nullptr)
		return new ScenarioBrowserHost;
	else if (::GetModuleHandleW(L"Skype.exe") != nullptr)
		return new ScenarioSkype;

	return nullptr;
}



BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID)
{
	static DebugConsole* pDbgConsole = nullptr;
	static Scenario* s_scenaro = nullptr;

	if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef _DEBUG
		pDbgConsole = new DebugConsole;
#endif  // _DEBUG

		if (s_scenaro == nullptr)
			s_scenaro = CreateScenario();

		if (s_scenaro == nullptr) {
			// not on our target list
			::MessageBoxW(nullptr, L"This DLL can only be loaded by a Skype process.", c_appName, MB_OK | MB_ICONERROR);
			return FALSE;
		}
		s_scenaro->Start();
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
		if (s_scenaro != nullptr) {
			s_scenaro->Stop();
			delete s_scenaro;
			s_scenaro = nullptr;
		}

		if (pDbgConsole != nullptr) {
			delete pDbgConsole;
			pDbgConsole = nullptr;
		}
	}

	return TRUE;
}
