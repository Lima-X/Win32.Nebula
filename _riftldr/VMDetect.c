#include "_riftldr.h"


// this has to be checked and fixed, its a terrible mess atm...

static BOOL ICheckVMware() {
	__try {
		__asm {
			push ebx

			mov  eax, 'VMXh'
			mov  ebx, 0      // any value but not the MAGIC VALUE
			mov  ecx, 10     // get VMWare version
			mov  edx, 'VX'   // port number
			in   eax, dx     // read port

			pop  ebx
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	return TRUE;
}

static BOOL ICheckVirtualBox() {
	HANDLE hDevice = CreateFileW(L"\\\\.\\VBoxMiniRdrDN", GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		return TRUE;
	} else
		return FALSE;
}

static DWORD ICVPCExceptionFilter(
	_In_ PEXCEPTION_POINTERS ep
) {
	PCONTEXT pCt = ep->ContextRecord;
	pCt->Ebx = (DWORD)-1; // Not running VPC
	pCt->Eip += 4; // skip past the "call VPC" opcodes

	return EXCEPTION_EXECUTE_HANDLER; // we can safely resume execution since we skipped faulty instruction
}
static BOOL ICheckVirtualPC() {
	__try {
		__asm {
			push   ebx

			mov    ebx, 0 // Flag
			mov    eax, 1 // VPC function number
			// call VPC
			__emit 0Fh
			__emit 3Fh
			__emit 07h
			__emit 0Bh

			pop    ebx
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		EXCEPTION_POINTERS* ep = GetExceptionInformation();
		PCONTEXT pCt = ep->ContextRecord;
		pCt->Ebx = (DWORD)-1; // Not running VPC
		pCt->Eip += 4; // skip past the "call VPC" opcodes
		return FALSE;
	}

	return TRUE;
}

// wtf
BOOL ICheckVmPresent() {
	BOOL bT = ICheckVMware();
	if (bT)	return TRUE;
	bT = ICheckVirtualBox();
	if (bT)	return TRUE;
	bT = ICheckVirtualPC();
	return bT;
}