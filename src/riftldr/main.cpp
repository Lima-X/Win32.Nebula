#include "ldr.h"

void __cdecl CoreMain() {
	__try {
		*(char*)0x0 = 0;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		MessageBoxW(0, L"Seh Handler Executed", L"Seh", 0);
	}

	ExitProcess(S_SUCCESS);
}