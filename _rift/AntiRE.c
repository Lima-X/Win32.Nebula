#include "pch.h"
#include "_rift.h"

static DWORD WINAPI thAntiDebug(_In_ PVOID pParam);

VOID fnAntiRE() {
    CreateThread(0, 0, thAntiDebug, 0, 0, 0);

}

static DWORD WINAPI thAntiDebug(
    _In_ PVOID pParam
) {
    while (TRUE) {


        Sleep(1000);
    }
}