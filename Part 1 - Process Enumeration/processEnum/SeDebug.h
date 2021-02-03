#include <TlHelp32.h>


BOOL enablePriv(void) {

	//Fetch privilege value for SeDebugPriv
	// LookupPrivilegeValue

	LUID	privLUID;

	if (!LookupPrivilegeValue(
		NULL,
		_T("SeDebugPrivilege"),
		&privLUID
	))
	{
		ErrorExit(TEXT("LookupPrivilegeValue()"));
	}

	// Setting up Token Privileges

	TOKEN_PRIVILEGES tp;

	tp.PrivilegeCount = 1; // count of Privileges to be modified
	tp.Privileges[0].Luid = privLUID; // The LUID of the privilege to be modified 
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // enable this privilege


	// Setting up parameters for OpenProcessToken API

	HANDLE	currentProcessHandle = GetCurrentProcess();
	HANDLE	processToken; // A pointer to a handle that identifies the newly opened access token when the function returns. Will be required for AdjustPriv API

	// TOKEN_ADJUST_PRIVILEGES 	Required to enable or disable the privileges in an access token.

	if (!OpenProcessToken(currentProcessHandle, TOKEN_ADJUST_PRIVILEGES, &processToken))
	{
		ErrorExit(TEXT("LookupPrivilegeValue()"));
	}

	// Enabling privileges in the cureent processes's Token

	if (!AdjustTokenPrivileges(processToken, FALSE, &tp, 0, NULL, NULL))
	{
		ErrorExit(TEXT("AdjustTokenPrivileges"));
	}

	return TRUE;

}