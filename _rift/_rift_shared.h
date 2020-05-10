#ifndef _shared_HIG
#define _shared_HIG

/* Xoshiro PRNG Algorithm : Xoshiro.c */
typedef struct {
	UINT32 ran : 3;
	UINT32 lj : 8;
	UINT32 sj : 8;
	UINT32 ns : 13;
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
	VOID(*fnLJump128)(PVOID pui32S);
	VOID(*fnSJump128)(PVOID pui32S);
	UINT32(*fnURID32)(UINT32 ui32Max, UINT32 ui32Min, PVOID pui32S);
	float (*fnURRD24)(PVOID pui32S);
	PVOID(*fnAllocXSR)(UINT64 ui64Seed, sXSRP sParamA, sSMP sParamB);
	PVOID(*fnRelocXSR)(PVOID pui32S, UINT64 ui64Seed, sXSRP sParamA, sSMP sParamB);
	PVOID(*fnCopyXSR)(PVOID pui32S);
	VOID(*fnDelocXSR)(PVOID pui32S);

	PWCHAR g_wcsMFN;
	PWCHAR g_wcsCD;
} sEpTDll, * pEpTDll;

#endif // !_shared_HIG