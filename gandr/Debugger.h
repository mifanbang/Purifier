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

#include <memory>
#include <unordered_map>
#include <string>

#include "DebugSession.h"



namespace gan {



// ---------------------------------------------------------------------------
// class Debugger - a debugger responsible for sending events to DebugSession
//                  objects managed by it
// ---------------------------------------------------------------------------

class Debugger
{
public:
	enum class EventLoopResult
	{
		AllDetached,
		ExitRequested,  // return due to SetMainLoopExitFlag() being called
		ErrorOccurred
	};

	using IdList = std::vector<DebugSession::Identifier>;


	Debugger() noexcept;
	~Debugger();

	EventLoopResult EnterEventLoop();

	template <typename T, typename... Arg>
	bool AddSession(Arg&&... arg)
	{
		std::shared_ptr<DebugSession> pSession = std::make_shared<T>(std::forward<Arg>(arg)...);
		return AddSessionInstance(pSession);
	}

	bool RemoveSession(DebugSession::Identifier sessionId, DebugSession::EndOption option);
	void RemoveAllSessions(DebugSession::EndOption option);
	void GetSessionList(IdList& output) const;


private:
	inline void RequestEventLoopExit() noexcept
	{
		m_flagEventLoopExit = true;
	}

	bool AddSessionInstance(const std::shared_ptr<DebugSession>& pSession);


	using SessionMap = std::unordered_map<DebugSession::Identifier, std::shared_ptr<DebugSession>>;
	SessionMap m_sessions;

	bool m_flagEventLoopExit;  // flag for main loop
};



}  // namespace gan
