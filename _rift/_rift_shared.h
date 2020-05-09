#ifndef _shared_HIG
#define _shared_HIG

typedef struct {
	VOID(*pfnXorEncrypt)(PVOID pData, UINT32 nDataLen, PVOID pKey, UINT16 nKeyLen);
	VOID(*pfnXorDecrypt)(PVOID pData, UINT32 nDataLen, PVOID pKey, UINT16 nKeyLen);
	PWCHAR g_wcsMFN;
	PWCHAR g_wcsCD;
} sEpTDll;

#endif // !_shared_HIG