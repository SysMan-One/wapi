//////////////////////////////////////////////////////////////////////////
//                                                                      //
//   wapi.cpp - prototypes WinAPI functions                             //
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

#include "wapi.h"

namespace _wapi_api {
	HMODULE GetNTDLLHmodule()
	{
		HMODULE hDLL = GetModuleHandle(TEXT("ntdll.dll"));
		if (hDLL == NULL)
		{
#ifdef WAPI_FULL_LOG
			printf("[-] Failed to find ntdll.dll\n");
#endif
			return NULL;
		}
#ifdef WAPI_FULL_LOG
		printf("[+] Got ntdll.dll handle. Address --> 0x%x\n", (size_t)hDLL);
#endif
		return hDLL;
	}
}

namespace _wapi_ntdll {
	////////////////////////////////////////////////////////////////////
	// APC

	//----------------------------
	// KiUserApcDispatcher
	VOID NTAPI	KiUserApcDispatcher(
		IN PVOID                Unused1,
		IN PVOID                Unused2,
		IN PVOID                Unused3,
		IN PVOID                ContextStart,
		IN PVOID                ContextBody)
	{
		typedef VOID(NTAPI *KiUserApcDispatcherPrototype)(PVOID	Unused1, PVOID Unused2, PVOID Unused3, PVOID ContextStart, PVOID ContextBody);
		HMODULE hDLL = _wapi_api::GetNTDLLHmodule();
		if (hDLL == NULL)
			return;
		KiUserApcDispatcherPrototype UserApcDispatcher = (KiUserApcDispatcherPrototype)GetProcAddress(hDLL, "KiUserApcDispatcher");
		if (UserApcDispatcher == NULL)
		{
#ifdef WAPI_FULL_LOG
			printf("[-] Failed to find KiUserApcDispatcher\n");
#endif
			return;
		}
#ifdef WAPI_FULL_LOG
		printf("[+] Found KiUserApcDispatcher address. Address --> 0x%x\n", (size_t)UserApcDispatcher);
		printf("[*] Calling KiUserApcDispatcher...\n");
#endif
		UserApcDispatcher(Unused1, Unused2, Unused3, ContextStart, ContextBody);
	}

	//----------------------------
	// NtAlertThread
	NTSTATUS NTAPI	NtAlertThread(
		IN HANDLE               ThreadHandle)
	{
		typedef NTSTATUS(NTAPI *NtAlertThreadPrototype)(HANDLE ThreadHandle);
		HMODULE hDLL = _wapi_api::GetNTDLLHmodule();
		if (hDLL == NULL)
			return NULL;
		NtAlertThreadPrototype ntAlertThread = (NtAlertThreadPrototype)GetProcAddress(hDLL, "NtAlertThread");
		if (ntAlertThread == NULL)
		{
#ifdef WAPI_FULL_LOG
			printf("[-] Failed to find NtAlertThread\n");
#endif
			return NULL;
		}
#ifdef WAPI_FULL_LOG
		printf("[+] Found NtAlertThread address. Address --> 0x%x\n", (size_t)ntAlertThread);
		printf("[*] Calling NtAlertThread...\n");
#endif
		NTSTATUS result = ntAlertThread(ThreadHandle);
#ifdef WAPI_FULL_LOG
		printf("[+] thread alerted state (returned) --> %d\n\n", result);
		return result;
#endif
	}

	//----------------------------
	// NtCallbackReturn
	NTSTATUS NTAPI NtCallbackReturn(
		IN PVOID                Result OPTIONAL,
		IN ULONG                ResultLength,
		IN NTSTATUS             Status)
	{
		typedef NTSTATUS(NTAPI *CallbackReturnPrototype)(PVOID Result OPTIONAL, ULONG ResultLength, NTSTATUS Status);
		HMODULE hDLL = _wapi_api::GetNTDLLHmodule();
		if (hDLL == NULL)
			return NULL;
		CallbackReturnPrototype ntCallbackReturn = (CallbackReturnPrototype)GetProcAddress(hDLL, "NtCallbackReturn");
		if (ntCallbackReturn == NULL)
		{
#ifdef WAPI_FULL_LOG
			printf("[-] Failed to find NtCallbackReturn\n");
#endif
			return NULL;
		}
#ifdef WAPI_FULL_LOG
		printf("[+] Found NtCallbackReturn address. Address --> 0x%x\n", (size_t)ntCallbackReturn);
		printf("[*] Calling NtCallbackReturn...\n");
#endif
		NTSTATUS result = ntCallbackReturn(Result, ResultLength, Status);
#ifdef WAPI_FULL_LOG
		printf("[+] returned --> %d\n\n", result);
		return result;
#endif
	}



	////////////////////////////////////////////////////////////////////
	// HASH

	//----------------------------
	// RtlComputeCrc32
	INT NTAPI RtlComputeCrc32(
		IN INT						accumCRC32,
		IN const BYTE*				buffer,
		IN UINT						buflen)
	{
		typedef INT(NTAPI *RtlComputeCrc32Prototype)(INT accumCRC32, const BYTE* buffer, UINT buflen);
		HMODULE hDLL = _wapi_api::GetNTDLLHmodule();
		if (hDLL == NULL)
			return NULL;
		RtlComputeCrc32Prototype ComputeCrc32 = (RtlComputeCrc32Prototype)GetProcAddress(hDLL, "RtlComputeCrc32");
		if (ComputeCrc32 == NULL)
		{
#ifdef WAPI_FULL_LOG
			printf("[-] Failed to find RtlComputeCrc32\n");
#endif
			return NULL;
		}
#ifdef WAPI_FULL_LOG
		printf("[+] Found RtlComputeCrc32 address. Address --> 0x%x\n", (size_t)ComputeCrc32);
		printf("[*] Calling RtlComputeCrc32...\n");
#endif
		INT iCRC32 = ComputeCrc32(accumCRC32, (BYTE*)buffer, 3);
#ifdef WAPI_FULL_LOG
		printf("[+] Computed CRC32 --> 0x%x\n\n", iCRC32);
#endif
		return iCRC32;
	}



	////////////////////////////////////////////////////////////////////
	// TIME

	//----------------------------
	// NtGetTickCount
	ULONG NTAPI NtGetTickCount()
	{
		typedef INT(NTAPI *NtGetTickCountPrototype)();
		HMODULE hDLL = _wapi_api::GetNTDLLHmodule();
		if (hDLL == NULL)
			return NULL;
		NtGetTickCountPrototype GetTickCount = (NtGetTickCountPrototype)GetProcAddress(hDLL, "NtGetTickCount");
		if (GetTickCount == NULL)
		{
#ifdef WAPI_FULL_LOG
			printf("[-] Failed to find NtGetTickCount\n");
#endif
			return NULL;
		}
#ifdef WAPI_FULL_LOG
		printf("[+] Found NtGetTickCount address. Address --> 0x%x\n", (size_t)GetTickCount);
		printf("[*] Calling NtGetTickCount...\n");
#endif
		ULONG ticks = GetTickCount();
#ifdef WAPI_FULL_LOG
		printf("[+] ticks --> %d\n\n", ticks);
#endif
		return ticks;
	}
}