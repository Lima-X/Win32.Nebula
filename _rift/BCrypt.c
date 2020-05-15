#include "pch.h"
#include "_rift.h"

static BCRYPT_ALG_HANDLE cahRNG;
NTSTATUS fnBCryptOpenRNGH() {
	return BCryptOpenAlgorithmProvider(cahRNG, BCRYPT_RNG_ALGORITHM, 0, 0);
}
NTSTATUS fnBCryptCloseRNGH() {
	return BCryptCloseAlgorithmProvider(cahRNG, 0);
}

PVOID fnBCryptGenRandomFB(
	_In_ PVOID  pBuffer,
	_In_ UINT32 cbBufferSize
) {
	if (pBuffer)
		BCryptGenRandom(cahRNG, pBuffer, cbBufferSize, 0);
	return pBuffer;
}