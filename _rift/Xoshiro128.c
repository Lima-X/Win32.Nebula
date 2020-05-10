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

static UINT64 fnNextSM64(
	_Inout_ PUINT64 pui64SM
) {
	UINT64 ui64X = (*pui64SM += 0x9e3779b97f4a7c15);
	ui64X = (ui64X ^ (ui64X >> 30)) * 0xbf58476d1ce4e5b9;
	ui64X = (ui64X ^ (ui64X >> 27)) * 0x94d049bb133111eb;
	return ui64X ^ (ui64X >> 31);
}
static inline VOID fnSMPInit(
	_Inout_ PUINT64 pui64Seed,
	_Inout_ pXSRP   pXSR,
	_Inout_ pSMP    pSM
) {
	/* SM64 Init */
	if (pSM->ran)
		pSM->ns |= fnNextSM64(pui64Seed) >> 57;
	for (UINT16 i = 0; i < pSM->ns; i++)
		fnNextSM64(pui64Seed);

	/* XSR Init */
	if (pXSR->ran & 0b100)
		pXSR->lj |= fnNextSM64(pui64Seed) >> 56;
	if (pXSR->ran & 0b10)
		pXSR->sj |= fnNextSM64(pui64Seed) >> 56;
	if (pXSR->ran & 0b1)
		pXSR->ns |= fnNextSM64(pui64Seed) >> 51;
}
static inline PVOID fnSInit(
	_Inout_ PUINT64 pui64Seed
) {
	PVOID pS = malloc(sizeof(UINT32) * 4);
	if (pS)
		for (UINT8 i = 0; i < 4; i++)
			((PUINT32)pS)[i] = fnNextSM64(pui64Seed) >> 32;
	else
		return 0;

	return pS;
}
static inline VOID fnXSRInit(
	_Inout_ PVOID pS,
	_In_    sXSRP sXSR
) {
	for (UINT8 i = 0; i < sXSR.lj; i++)
		fnLJump128(pS);
	for (UINT8 i = 0; i < sXSR.sj; i++)
		fnSJump128(pS);
	for (UINT16 i = 0; i < sXSR.ns; i++)
		fnNext128(pS);
}

PVOID fnAllocXSR(
	_In_ UINT64 ui64Seed,
	_In_ sXSRP  sParamA,
	_In_ sSMP   sParamB
) {
	fnSMPInit(&ui64Seed, &sParamA, &sParamB);

	PVOID pS = fnSInit(&ui64Seed);
	if (pS) {
		for (UINT8 i = 0; i < 4; i++)
			((PUINT32)pS)[i] = fnNextSM64(&ui64Seed) >> 32;

		fnXSRInit(pS, sParamA);
	} else
		return 0;

	return pS;
}
PVOID fnRelocXSR(
	_Inout_ PVOID  pS,
	_In_    UINT64 ui64Seed,
	_In_    sXSRP  sParamA,
	_In_    sSMP   sParamB
) {
	if (!pS)
		return 0;

	fnSMPInit(&ui64Seed, &sParamA, &sParamB);

	for (UINT8 i = 0; i < 4; i++)
		((PUINT32)pS)[i] = fnNextSM64(&ui64Seed) >> 32;

	fnXSRInit(pS, sParamA);
	return pS;
}
PVOID fnCopyXSR(
	_In_ PVOID pS
) {
	if (!pS)
		return 0;

	PVOID pui32SC = malloc(sizeof(UINT32) * 4);
	if (!pui32SC)
		return 0;

	memcpy(pui32SC, pS, sizeof(UINT32) * 4);

	return pui32SC;
}
VOID fnDelocXSR(
	_Inout_ PVOID pS
) {
	if (!pS)
		return;

	free(pS);
	pS = 0;
}