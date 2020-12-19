#include "ldr.h"

N_PROTECTEDX void __cdecl CoreMain() {
	__try {
		*(char*)0x0 = 0;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		__debugbreak();
	}

	ExitProcess(SUCCESS);
}