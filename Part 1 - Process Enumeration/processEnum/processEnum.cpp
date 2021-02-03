#include <Windows.h>
#include <tchar.h>
#include <WtsApi32.h>
#include <sddl.h>
#include <iostream>
#include "Header.h"
#include "SeDebug.h"
#include <strsafe.h>

#pragma comment(lib, "wtsapi32")
#pragma comment(lib, "Advapi32")

#define MAX_ACCOUNTNAME_LEN 1024
#define MAX_DOMAINNAME_LEN 1024

int main(void)
{

	// Enabling SeDebugPrivilege
	enablePriv();

	DWORD level = 1;
	PWTS_PROCESS_INFO_EX processListing = NULL;
	DWORD processCount = 0;
	DWORD dw = GetLastError();

	if (!WTSEnumerateProcessesEx(
		WTS_CURRENT_SERVER_HANDLE,
		&level,
		WTS_ANY_SESSION,
		(LPTSTR*)&processListing,
		&processCount))
	{
		ErrorExit(TEXT("WTSEnumerateProcessesEx"));
		//std::cout << "Failed with error code: %d" << dw;
	}


	_tprintf(_T("Processes found: %d\n\n"), processCount);
	_tprintf(_T("#\tPID\tHandles\tThreads\tProcess Name\tSID\tAccount\n\n"));

	LPTSTR stringSID = NULL;
	PWTS_PROCESS_INFO_EX originalPtr = processListing;


	for (DWORD counter = 1; counter <= processCount; counter++)
	{
		_tprintf(_T("%d\t"), counter);
		_tprintf(_T("%d\t"), processListing->ProcessId);
		_tprintf(_T("%d\t"), processListing->HandleCount);
		_tprintf(_T("%d\t"), processListing->NumberOfThreads);
		_tprintf(_T("%s\t"), processListing->pProcessName);

		// Printing the SID and associated accounts
		// MSDN - https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsida

		if (!ConvertSidToStringSid(
			processListing->pUserSid,
			&stringSID))
		{
			_tprintf(_T("-\t"));
			//ErrorExit(TEXT("ConvertSidToStringSid"));
			//std::cout << "Failed with error code: %d", dw;
		}
		else
		{
			_tprintf(_T("%s\t"), stringSID);
			LocalFree((HLOCAL)stringSID);
		}

		TCHAR accountName[MAX_ACCOUNTNAME_LEN];
		DWORD bufferLen = MAX_ACCOUNTNAME_LEN;
		TCHAR domainName[MAX_DOMAINNAME_LEN];
		DWORD domainNameBufferLen = MAX_DOMAINNAME_LEN;
		SID_NAME_USE peUse;

		if (!LookupAccountSid(
			NULL,
			processListing->pUserSid,
			accountName,
			&bufferLen,
			domainName,
			&domainNameBufferLen,
			&peUse)
			)
		{
			//ErrorExit(TEXT("LookupAccountSid"));
			_tprintf(_T("\n"));
		}
		else
		{
			_tprintf(_T("%s\\%s\n"), domainName, accountName);
		}

		processListing++;

	}

	if (!WTSFreeMemoryEx(WTSTypeProcessInfoLevel1, originalPtr, processCount))
	{

		ErrorExit(TEXT("WTSFreeMemoryEx"));
		//std::cout << "Failed with error code: %d" << dw;
	}

	processListing = NULL;
	_tprintf(_T("\n\nDone! Press any key to exit. \n"));
	getchar();
	return 0;
}

