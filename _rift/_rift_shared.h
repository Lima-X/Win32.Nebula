#ifndef _shared_HIG
#define _shared_HIG
#include "config.h"

/* Xoshiro PRNG Algorithm : Xoshiro.c */
typedef struct {
#if _DISABLE_JUMPS == 0
	UINT32 ran : 3;
	UINT32 lj : 8;
	UINT32 sj : 8;
	UINT32 ns : 13;
#else
	UINT16 ran : 3;
	UINT16 ns : 13;
#endif
} sXSRP, * pXSRP;
typedef struct {
	UINT8 ran : 1;
	UINT8 ns : 7;
} sSMP, * pSMP;

/* Export Data to Dll Structure */
typedef struct {
	VOID(*pfnXorEncrypt)(PVOID pData, UINT32 nDataLen, PVOID pKey, UINT16 nKeyLen);
	VOID(*pfnXorDecrypt)(PVOID pData, UINT32 nDataLen, PVOID pKey, UINT16 nKeyLen);

	UINT32(*fnNext128ss)(PVOID pui32S);
	UINT32(*fnNext128p)(PVOID pui32S);
#if _DISABLE_JUMPS == 0
	VOID(*fnLJump128)(PVOID pui32S);
	VOID(*fnSJump128)(PVOID pui32S);
#endif
	UINT32(*fnURID32)(UINT32 ui32Max, UINT32 ui32Min, PVOID pui32S);
	float (*fnURRD24)(PVOID pui32S);
	PVOID(*fnAllocXSR)(pXSRP sParamA, pSMP sParamB);
	BOOL(*fnRelocXSR)(PVOID pui32S, pXSRP sParamA, pSMP sParamB);
	PVOID(*fnCopyXSR)(PVOID pui32S);
	VOID(*fnDelocXSR)(PVOID pui32S);

	PWCHAR g_wcsMFN;
	PWCHAR g_wcsCD;
} sEpTDll, * pEpTDll;

#endif // !_shared_HIG