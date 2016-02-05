//////////////////////////////////////////////////////////////////////////
//                                                                      //
//   wapi.h - prototypes WinAPI functions                               //
//   Created by:                                                        //
//   @nummer aka @nummerok                                              //
//   05.02.2016                                                         //
//                                                                      //
//   modified: 05.02.2016                                               //
//                                                                      //
//   undocumented WinAPI functions                                      //
//                                                                      //
//   https://github.com/Nummer/wapi                                     //
//                                                                      //
//////////////////////////////////////////////////////////////////////////

#pragma once

#undef WAPI_FULL_LOG

#include <windows.h>

#if ((defined(_DEBUG) || defined(DEBUG)) && !defined(WAPI_NO_LOG))
#define WAPI_FULL_LOG
#include <stdio.h>
#endif

namespace _wapi_api {
	HMODULE GetNTDLLHmodule();
}

namespace _wapi_ntdll {
	////////////////////////////////////////////////////////////////////
	// APC

	//----------------------------
	// KiUserApcDispatcher
	NTSYSAPI VOID NTAPI	KiUserApcDispatcher(
			IN PVOID                Unused1,
			IN PVOID                Unused2,
			IN PVOID                Unused3,
			IN PVOID                ContextStart,
			IN PVOID                ContextBody);

	//----------------------------
	// NtAlertThread
	NTSYSAPI NTSTATUS NTAPI	NtAlertThread(
			IN HANDLE               ThreadHandle);
	
	//----------------------------
	// NtCallbackReturn
	NTSYSAPI NTSTATUS NTAPI NtCallbackReturn(
			IN PVOID                Result OPTIONAL,
			IN ULONG                ResultLength,
			IN NTSTATUS             Status);

	
	
	////////////////////////////////////////////////////////////////////
	// HASH

	//----------------------------
	// RtlComputeCrc32
	NTSYSAPI INT NTAPI RtlComputeCrc32(
		IN INT						accumCRC32,
		IN const BYTE*				buffer,
		IN UINT						buflen);
}