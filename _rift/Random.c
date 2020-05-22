#include "pch.h"
#include "_rift.h"

const WCHAR szCharSet[] = {
	L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	L"abcdefghijklmnopqrstuvwxyz"
	L"^1234567890´°!§$&()=`{[]},"
	L"-;_"
};

VOID fnGenRandomStringW(
	_Inout_ PVOID  pBuffer,
	_In_    SIZE_T nBuffer
) {
	if (pBuffer) {
		for (SIZE_T i = 0; i < nBuffer; i++) {
			((PWCHAR)pBuffer)[i] = szCharSet[fnURID(0, sizeof(szCharSet))];
		}
	}
}