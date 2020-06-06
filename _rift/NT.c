#include "pch.h"
#include "_rift.h"

/* I could just link to RtlAdjustPrivilege and call that,
   but where is the fun in that :D
   so lets to it the normal way (the manual one).
   As a side effect the exe won't import RtlAdjustPrivilege...
   which will reduce detection (lol if it weren't for the other stuff). */
BOOL fnAdjustPrivilege(
	_In_ PCWSTR szPrivilege,
	_In_ BOOL   bEnablePrivilege
) {
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	LUID id;
	if (!LookupPrivilegeValueW(0, szPrivilege, &id))
		return FALSE;

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = id;
	tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), 0, 0))
		return FALSE;
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}