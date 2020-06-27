#include "pch.h"
#include "_rift.h"

BOOL fnAntiRE() {
	IAntiDllInject();
	IAntiDebug();
}

BOOL fnErasePeHeader() {
	// Get Nt Headers
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)g_PIB->hMH;
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pDosHdr + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	DWORD dwProtect;
	SIZE_T nOHdr = pOHdr->SizeOfHeaders;
	VirtualProtect(g_PIB->hMH, nOHdr, PAGE_EXECUTE_READWRITE, &dwProtect);
	SecureZeroMemory(g_PIB->hMH, nOHdr);
	VirtualProtect(g_PIB->hMH, nOHdr, dwProtect, &dwProtect);
	return TRUE;
}

EXTERN_C CONST BYTE e_HashSig[16];
EXTERN_C CONST CHAR e_pszSections[3][8];
FORCEINLINE BOOL IHashCodeSection() {
	// Read Binary File
	SIZE_T nFileSize;
	PVOID pFile = AllocReadFileW(g_PIB->szMFN, &nFileSize);
	if (!pFile)
		return 0;

	// Get NT Headers
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pFile;
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pDosHdr + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	// Prepare Hashing
	BCRYPT_ALG_HANDLE ah;
	BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
	BCRYPT_HASH_HANDLE hh;
	BCryptCreateHash(ah, &hh, NULL, 0, NULL, 0, NULL);

	for (UINT8 i = 0; i < pFHdr->NumberOfSections; i++) {
		// Get Section and Check if Type is accepted
		PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((PTR)pOHdr + (PTR)pFHdr->SizeOfOptionalHeader) + i);
		if (!((pSHdr->Characteristics & IMAGE_SCN_CNT_CODE) || (pSHdr->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)))
			continue;

		// Check for Special Section
		BOOLEAN bFlag;
		for(UINT8 j = 0; j < (sizeof(e_pszSections) / sizeof(e_pszSections[0])); j++) {
			bFlag = TRUE;
			for (UINT8 n = 0; n < IMAGE_SIZEOF_SHORT_NAME; n++) {
				if (pSHdr->Name[n] != e_pszSections[j][n]) {
					bFlag = FALSE;
					break;
				}
			} if (bFlag) {
				bFlag = j + 1;
				break;
			}
		}

		// Set Section Pointers
		PVOID pSection = (PVOID)((PTR)pDosHdr + (PTR)pSHdr->PointerToRawData);
		SIZE_T nSection = pSHdr->SizeOfRawData;

		// Select what to to
		if (bFlag == 1) {
			PVOID pHash = 0;

			// Find Hash Signature
			for (UINT j = 0; j < nSection - MD5_SIZE; j++) {
				bFlag = TRUE;
				for (UINT8 n = 0; n < MD5_SIZE; n++) {
					if (((PBYTE)pSection)[j + n] != e_HashSig[n]) {
						bFlag = FALSE;
						break;
					}
				} if (bFlag) {
					pHash = (PVOID)((PTR)pSection + j);
					break;
				}
			}

			// Hash only Data surrounding the Hash
			SIZE_T nRDataP1 = (PTR)pHash - (PTR)pSection;
			BCryptHashData(hh, pSection, nRDataP1, NULL);
			SIZE_T nRDataP2 = ((PTR)pSection + nSection) - ((PTR)pHash + MD5_SIZE);
			BCryptHashData(hh, (PUCHAR)((PTR)pHash + MD5_SIZE), nRDataP2, NULL);
		} else if (bFlag >= 2)
			continue;
		else
			BCryptHashData(hh, pSection, nSection, NULL);
	}

	PVOID pMd5 = AllocMemory(MD5_SIZE);
	BCryptFinishHash(hh, pMd5, MD5_SIZE, NULL);
	BCryptDestroyHash(hh);
	BCryptCloseAlgorithmProvider(ah, NULL);
	BOOL bT = EMd5Compare(pMd5, e_HashSig);
	FreeMemory(pMd5);
	return bT;
}

/* Thread Local Storage (TLS) Callback */
STATIC BOOLEAN l_bTlsFlag = TRUE;
EXTERN_C CONST BYTE e_SKey[28];
VOID NTAPI ITlsCb(
	_In_ PVOID DllHandle,
	_In_ DWORD dwReason,
	_In_ PVOID Reserved
) {
	UNREFERENCED_PARAMETER(DllHandle);
	UNREFERENCED_PARAMETER(dwReason);
	UNREFERENCED_PARAMETER(Reserved);
	if (l_bTlsFlag) {
		{	// Partially initialize PIB (Neccessary Fields only)
			HANDLE hPH = GetProcessHeap();
			g_PIB = (PPIB)HeapAlloc(hPH, NULL, sizeof(PIB));
			g_PIB->hPH = hPH;
			HMODULE hP = GetModuleHandleW(NULL);
			GetModuleFileNameW(hP, g_PIB->szMFN, MAX_PATH);
			ECryptBegin(e_SKey, &g_PIB->cibSK);
		}

		l_bTlsFlag = FALSE;
		BOOL bT = IHashCodeSection();
		if (bT)
			MessageBoxW(0, L"TLS InCorrect", 0, 0);
		else
			MessageBoxW(0, L"TLS Correct", 0, 0);
	}
}

#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_TlsCallback")
#pragma data_seg(".CRT$XLY")
PIMAGE_TLS_CALLBACK TlsCallback = ITlsCb;
#pragma data_seg()