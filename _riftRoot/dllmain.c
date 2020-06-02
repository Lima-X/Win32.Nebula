#include "pch.h"
#include "_riftRoot.h"

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ PVOID     pvReserved
) {
	UNREFERENCED_PARAMETER(pvReserved);

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:

		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:

		break;
	}

	return TRUE;
}