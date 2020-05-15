#include "pch.h"
#include "_rift.h"

static inline UINT32 fnRol32(
	_In_ UINT32 ui32X,
	_In_ UINT8  ui8K
) {
	return (ui32X << ui8K) | (ui32X >> (32 - ui8K));
}
static inline VOID fnNext128(
	_Inout_ PVOID pS
) {
	const UINT32 ui32T = ((PUINT32)pS)[1] << 9;
	((PUINT32)pS)[2] ^= ((PUINT32)pS)[0];
	((PUINT32)pS)[3] ^= ((PUINT32)pS)[1];
	((PUINT32)pS)[1] ^= ((PUINT32)pS)[2];
	((PUINT32)pS)[0] ^= ((PUINT32)pS)[3];
	((PUINT32)pS)[2] ^= ui32T;
	((PUINT32)pS)[3] = fnRol32(((PUINT32)pS)[3], 11);
}

UINT32 fnNext128ss(
	_Inout_ PVOID pS
) {
	const UINT32 ui32T = fnRol32(((PUINT32)pS)[1] * 5, 7) * 9;
	fnNext128(pS);
	return ui32T;
}
UINT32 fnNext128p(
	_Inout_ PVOID pS
) {
	const UINT32 ui32T = ((PUINT32)pS)[0] + ((PUINT32)pS)[3];
	fnNext128(pS);
	return ui32T;
}

#if _DISABLE_JUMPS == 0
static inline VOID fnJump128(
	_In_    PVOID ui32a4,
	_Inout_ PVOID pS
) {
	UINT32 ui32Sa = 0, ui32Sb = 0, ui32Sc = 0, ui32Sd = 0;
	for (UINT8 i = 0; i < 4; i++)
		for (UINT8 j = 0; j < 32; j++) {
			if (((PUINT32)ui32a4)[i] & (0x1U << j)) {
				ui32Sa ^= ((PUINT32)pS)[0];
				ui32Sb ^= ((PUINT32)pS)[1];
				ui32Sc ^= ((PUINT32)pS)[2];
				ui32Sd ^= ((PUINT32)pS)[3];
			}

			fnNext128(pS);
		}

	((PUINT32)pS)[0] = ui32Sa;
	((PUINT32)pS)[1] = ui32Sb;
	((PUINT32)pS)[2] = ui32Sc;
	((PUINT32)pS)[3] = ui32Sd;
}

VOID fnLJump128(
	_Inout_ PVOID pS
) {
	const UINT32 ui32a4J[] = {
		0xb523952e, 0x0b6f099f, 0xccf5a0ef, 0x1c580662
	};

	fnJump128(ui32a4J, pS);
}
VOID fnSJump128(
	_Inout_ PVOID pS
) {
	const UINT32 ui32a4J[] = {
		0x8764000b, 0xf542d2d3, 0x6fa035c3, 0x77f2db5b
	};

	fnJump128(ui32a4J, pS);
}
#endif

UINT32 fnURID32(
	_In_    UINT32 ui32Max,
	_In_    UINT32 ui32Min,
	_Inout_ PVOID  pS
) {
	UINT32 ui32Ret;
	const UINT32 ui32Range = (ui32Max - ui32Min) + 1;
	const UINT32 ui32Scale = (UINT32)-1 / ui32Range;
	const UINT32 ui32Limit = ui32Range * ui32Scale;

	do {
		ui32Ret = fnNext128ss(pS);
	} while (ui32Ret >= ui32Limit);

	ui32Ret /= ui32Scale;
	return ui32Ret + ui32Min;
}
float fnURRD24(
	_Inout_ PVOID pS
) {
	// 24 bits resolution: (r >> 8) * 2^(-24)
	return (fnNext128p(pS) >> 8) * (1.f / 0x1000000p0f);
	// 23 bits resolution: (r >> 9) * 2^(-23)
	// return (pS->fnP(pS->pS) >> 9) * (1.f / 0x800000p0f);
}

static inline VOID fnInitParam(
	_In_    BCRYPT_ALG_HANDLE cah,
	_Inout_ pXSRP             pXSR,
	_Inout_ pSMP              pSM
) {
#if _DISABLE_JUMPS == 0
	if ((pXSR->ran >> 2) & 0b1) {
		UINT8 ui8T;
		BCryptGenRandom(cah, &ui8T, sizeof(INT8), 0);
		pXSR->lj |= ui8T;
	} if ((pXSR->ran >> 1) & 0b1) {
		UINT8 ui8T;
		BCryptGenRandom(cah, &ui8T, sizeof(INT8), 0);
		pXSR->sj |= ui8T;
	}
#endif
	if (pXSR->ran & 0b1) {
		UINT16 ui16T;
		BCryptGenRandom(cah, &ui16T, sizeof(INT16), 0);
		pXSR->ns |= ui16T >> 3;
	}
}
static inline PVOID fnAllocState(
	_In_ BCRYPT_ALG_HANDLE cah
) {
	PVOID pS = HeapAlloc(g_hPH, 0, sizeof(INT32) * 4);
	if (pS)
		BCryptGenRandom(cah, pS, sizeof(INT32) * 4, 0);
	else
		return 0;

	return pS;
}
static inline VOID fnInitState(
	_Inout_ PVOID pS,
	_In_    pXSRP sXSR
) {
#if _DISABLE_JUMPS == 0
	for (UINT8 i = 0; i < sXSR->lj; i++)
		fnLJump128(pS);
	for (UINT8 i = 0; i < sXSR->sj; i++)
		fnSJump128(pS);
#endif
	for (UINT16 i = 0; i < sXSR->ns; i++)
		fnNext128(pS);
}

PVOID fnAllocXSR(
	_In_ pXSRP  sParamA,
	_In_ pSMP   sParamB
) {
	BCRYPT_ALG_HANDLE cah;
	NTSTATUS ntS = BCryptOpenAlgorithmProvider(&cah, BCRYPT_RNG_ALGORITHM, 0, 0);
	if (!ntS) {
		fnInitParam(cah, sParamA, sParamB);

		PVOID pS = fnAllocState(cah);
		if (pS)
			fnInitState(pS, sParamA);

		ntS = BCryptCloseAlgorithmProvider(cah, 0);
		return pS;
	} else
		SetLastError(ntS);

	return 0;
}
BOOL fnRelocXSR(
	_Inout_ PVOID  pS,
	_In_    pXSRP  sParamA,
	_In_    pSMP   sParamB
) {
	if (!pS)
		return 1;

	BCRYPT_ALG_HANDLE cah;
	NTSTATUS ntS = BCryptOpenAlgorithmProvider(&cah, BCRYPT_RNG_ALGORITHM, 0, 0);
	if (!ntS) {
		fnInitParam(cah, sParamA, sParamB);
		BCryptGenRandom(cah, pS, sizeof(INT32) * 4, 0);
		fnInitState(pS, sParamA);
		BCryptCloseAlgorithmProvider(cah, 0);
	} else
		return ntS;

	return 0;
}
PVOID fnCopyXSR(
	_In_ PVOID pS
) {
	if (!pS)
		return 0;

	PVOID pSC = HeapAlloc(g_hPH, 0, sizeof(UINT32) * 4);
	if (!pSC)
		return 0;

	CopyMemory(pSC, pS, sizeof(UINT32) * 4);

	return pSC;
}
VOID fnDelocXSR(
	_Inout_ PVOID pS
) {
	if (!pS)
		return;

	free(pS);
	pS = 0;
}