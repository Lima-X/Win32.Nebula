#include "_riftdll.h"

STATUS riftMain() {

}

DLLEX STATUS WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ void*     pvReserved
) {
	UNREFERENCED_PARAMETER(pvReserved);

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;

	case 4: // Execute Stage-2
		g_PIB = pvReserved;
		return riftMain();
	case 5: // System Shutdown
	}

	return TRUE;
}