#include "_riftdll.h"

status riftMain() {

	return NULL;
}

status WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ dword     fdwReason,
	_In_ void*     pvReserved
) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;

	case 4: // Execute Stage-2
		return riftMain();
	case 5: // System Shutdown
		;
	}

	return TRUE;
}