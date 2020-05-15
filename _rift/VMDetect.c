#include "pch.h"
#include "_rift.h"

static BOOL fnCheckVMware();
static BOOL fnCheckVirtualBox();
static BOOL fnCheckVirtualPC();

BOOL fnCheckVMPresent() {
	BOOL bT = fnCheckVMware();
	bT |= fnCheckVirtualBox();
	bT |= fnCheckVirtualPC();

	return bT;
}

static BOOL fnCheckVMware() {
	BOOL bRC = FALSE;

	__try {
		__asm {
			pushad

			mov    eax, 'VMXh'
			mov    ebx, 0      // any value but not the MAGIC VALUE
			mov    ecx, 10     // get VMWare version
			mov    edx, 'VX'   // port number
			in     eax, dx     // read port
			                   // on return EAX returns the VERSION
			cmp    ebx, 'VMXh' // is it a reply from VMWare?
			setz   [bRC]       // set return value

			popad
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
	}

	return bRC;
}

static BOOL fnCheckVirtualBox() {
	HANDLE hDevice = CreateFileW(L"\\\\.\\VBoxMiniRdrDN", GENERIC_READ,
		FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		return TRUE;
	} else
		return FALSE;
}

static inline DWORD fnCVPCExceptionFilter(
	_In_ PEXCEPTION_POINTERS ep
) {
	PCONTEXT pCt = ep->ContextRecord;
	pCt->Ebx = (DWORD)-1; // Not running VPC
	pCt->Eip += 4; // skip past the "call VPC" opcodes

	return EXCEPTION_CONTINUE_EXECUTION; // we can safely resume execution since we skipped faulty instruction
}
static BOOL fnCheckVirtualPC() {
	BOOL bRC = FALSE;

	__try {
		__asm {
			pushad
			mov    ebx, 0 // Flag
			mov    eax, 1 // VPC function number

			// call VPC
			__emit 0Fh
			__emit 3Fh
			__emit 07h
			__emit 0Bh

			test   ebx, ebx
			setz   [bRC] // set return value
			popad
		}
	} __except (fnCVPCExceptionFilter(GetExceptionInformation())) {
	}

	return bRC;
}