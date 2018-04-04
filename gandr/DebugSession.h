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

#include <windows.h>



namespace gan {



// ---------------------------------------------------------------------------
// class DebugSession - another process being atttached to by this process
// ---------------------------------------------------------------------------

class DebugSession
{
public:
	using Identifier = std::uint32_t;  // using system pid (a DWORD) as identifier

	struct CreateProcessParam
	{
		LPCWSTR imagePath;
		LPCWSTR args;
		LPCWSTR currentDir;
		LPSTARTUPINFOW startUpInfo;

		CreateProcessParam()
			: imagePath(nullptr)
			, args(nullptr)
			, currentDir(nullptr)
			, startUpInfo(nullptr)
		{ }
	};

	struct PreEvent
	{
		std::uint32_t eventCode;
		std::uint32_t threadId;
	};

	enum class ContinueStatus
	{
		ContinueThread,
		NotHandled,
		CloseSession
	};

	enum class EndOption
	{
		Kill,
		Detach
	};


	DebugSession(const CreateProcessParam& newProcParam);

	virtual ~DebugSession();

	void End(EndOption option);

	bool IsValid() const;

	inline Identifier GetId() const			{ return m_pid;	}
	inline const HANDLE GetHandle() const	{ return m_hProc; }


	virtual void OnPreEvent(const PreEvent& event) { }

	virtual ContinueStatus OnExceptionTriggered(const EXCEPTION_DEBUG_INFO& exceptionInfo) { return ContinueStatus::ContinueThread; }
	virtual ContinueStatus OnThreadCreated(const CREATE_THREAD_DEBUG_INFO& threadInfo) { return ContinueStatus::ContinueThread; }
	virtual ContinueStatus OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO& procInfo) { return ContinueStatus::ContinueThread; }
	virtual ContinueStatus OnThreadExited(const EXIT_THREAD_DEBUG_INFO& threadInfo) { return ContinueStatus::ContinueThread; }
	virtual ContinueStatus OnProcessExited(const EXIT_PROCESS_DEBUG_INFO& procInfo) { return ContinueStatus::CloseSession; }
	virtual ContinueStatus OnDllLoaded(const LOAD_DLL_DEBUG_INFO& dllInfo) { return ContinueStatus::ContinueThread; }
	virtual ContinueStatus OnDllUnloaded(const UNLOAD_DLL_DEBUG_INFO& dllInfo) { return ContinueStatus::ContinueThread; }
	virtual ContinueStatus OnStringOutput(const OUTPUT_DEBUG_STRING_INFO& stringInfo) { return ContinueStatus::ContinueThread; }
	virtual ContinueStatus OnRipEvent(const RIP_INFO& ripInfo) { return ContinueStatus::ContinueThread; }


private:
	Identifier m_pid;
	HANDLE m_hProc;
};



}  // namespace gan
