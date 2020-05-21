#include "pch.h"
#include "_riftdll.h"

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ PVOID     pvReserved
) {
	UNREFERENCED_PARAMETER(pvReserved);

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
		return TRUE;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		return TRUE;
	}
}

DLLAPI BOOL fnDllInit(int a) {
	return a;
}