// This project is just a mess,
// most of the sizes are not calculated dynamically and are hard coded,
// also there're no actual sanity checks as i didn't care for them.
// this is just a support tool after all
// and only serves the purpose to prepare files for the loader.
// tbh i just wanted to be done with this as it is already 300+ lines
// for just a support tool (why do i do this to myself)
// I should also add that this tool does NOT clean up properly,
// as it isn't required, the actual decryption module in the loader does.

// wow, this file is just getting worse and worse,
// tbh i should just rewrite it at somepoint, maybe when the actuall thing works...
// to safe some space right now i'll just remove some of the sanity checks
// ..i'll add them back in maybe later or idk.

#include "_riftTool.h"

extern CONST BYTE e_HashSig[16];
extern CONST CHAR e_pszSections[3][8];

INT wmain(
	_In_     INT    argc,
	_In_     PWCHAR argv[],
	_In_opt_ PWCHAR envp[]
) {
	UNREFERENCED_PARAMETER(envp);
	{	// Initialize Process Information block
		HANDLE hPH = GetProcessHeap();
		g_PIB = (PPIB)HeapAlloc(hPH, 0, sizeof(PIB));
		g_PIB->hPH = hPH;
		GetCurrentDirectoryW(MAX_PATH, g_PIB->szCD);
	}
	g_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
	g_pBuf = AllocMemory(0x800 * sizeof(WCHAR));
	// Safe CMD
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(g_hCon, &csbi);

	if (argc ==  3) {
		if (!lstrcmpW(argv[1], L"/gk")) {
			// Generate Random Aes128 Key
			BCRYPT_ALG_HANDLE ahAes, ahRng;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			nts = BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);
			PBYTE pKey = AllocMemory(AES_KEY_SIZE);
			nts = BCryptGenRandom(ahRng, pKey, AES_KEY_SIZE, 0);
			nts = BCryptCloseAlgorithmProvider(ahRng, 0);
			BCRYPT_KEY_HANDLE khAes;
			nts = BCryptGenerateSymmetricKey(ahAes, &khAes, 0, 0, pKey, AES_KEY_SIZE, 0);
			FreeMemory(pKey);

			// Export AesBlob
			SIZE_T nResult;
			PVOID pKeyE = AllocMemory(AES_BLOB_SIZE);
			nts = BCryptExportKey(khAes, 0, BCRYPT_KEY_DATA_BLOB, pKeyE, AES_BLOB_SIZE, &nResult, 0);
			nts = BCryptDestroyKey(khAes);
			BCryptCloseAlgorithmProvider(ahAes, 0);

			// Save Aes Blob
			PWSTR szFileName = AllocMemory(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->szCD, argv[2]);
			nts = WriteFileCW(szFileName, 0, pKeyE, AES_BLOB_SIZE);
			FreeMemory(szFileName);
			FreeMemory(pKeyE);
		} else if (!lstrcmpW(argv[1], L"/pa")) {
			// Load Executable/Image
			PWSTR szFileName = AllocMemory(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->szCD, argv[2]);
			SIZE_T nFile;
			PVOID pFile = ReadFileCW(szFileName, 0, &nFile);
			if (!pFile)
				goto EXIT;

			// Get Nt Headers
			PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pFile;
			PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pDosHdr + pDosHdr->e_lfanew);
			if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
				goto EXIT;
			PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
			PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
			if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
				goto EXIT;

			// Prepare Hashing
			BCRYPT_ALG_HANDLE ah;
			BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, 0, 0);
			BCRYPT_HASH_HANDLE hh;
			BCryptCreateHash(ah, &hh, 0, 0, 0, 0, 0);

			// Hash Sections
			PVOID pHash = 0;
			for (UINT8 i = 0; i < pFHdr->NumberOfSections; i++) {
				// Get Section and Check if Type is accepted
				PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((PTR)pOHdr + (PTR)pFHdr->SizeOfOptionalHeader) + i);
				if (!((pSHdr->Characteristics & IMAGE_SCN_CNT_CODE) || (pSHdr->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)))
					continue;

				// Check for Special Section
				BOOLEAN bFlag;
				for (UINT8 j = 0; j < (sizeof(e_pszSections) / sizeof(e_pszSections[0])); j++) {
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
				PVOID pSection = (PTR)pDosHdr + (PTR)pSHdr->PointerToRawData;
				SIZE_T nSection = pSHdr->SizeOfRawData;

				// Select what to to
				if (bFlag == 1) {
					for (UINT j = 0; j < nSection - MD5_SIZE; j++) {
						bFlag = TRUE;
						for (UINT8 n = 0; n < MD5_SIZE; n++) {
							if (((PBYTE)pSection)[j + n] != e_HashSig[n]) {
								bFlag = FALSE;
								break;
							}
						} if (bFlag) {
							pHash = (PTR)pSection + j;
							break;
						}
					}

					SIZE_T nRDataP1 = (PTR)pHash - (PTR)pSection;
					BCryptHashData(hh, pSection, nRDataP1, 0);
					SIZE_T nRDataP2 = ((PTR)pSection + nSection) - ((PTR)pHash + MD5_SIZE);
					BCryptHashData(hh, (PTR)pHash + MD5_SIZE, nRDataP2, 0);
				} else if (bFlag >= 2)
					continue;
				else
					BCryptHashData(hh, pSection, nSection, 0);
			}

			// Finish Hash
			PVOID pMd5 = AllocMemory(MD5_SIZE);
			BCryptFinishHash(hh, pMd5, MD5_SIZE, 0);
			BCryptDestroyHash(hh);
			BCryptCloseAlgorithmProvider(ah, 0);

			// Patch Image
			CopyMemory(pHash, pMd5, MD5_SIZE);
			FreeMemory(pMd5);

			// Commit Changes to Image
			WriteFileCW(szFileName, 0, pFile, nFile);
			FreeMemory(pFile);
			FreeMemory(szFileName);
		} else
			fnPrintF(L"Unknown Command\n", CON_ERROR);
	} else if (!lstrcmpW(argv[1], L"/ec")) {
		if (argc == 5) {
			// Load WrapKey
			PWSTR szFileName = AllocMemory(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->szCD, argv[3]);
			SIZE_T nFile;
			PVOID pWKey = ReadFileCW(szFileName, 0, &nFile);
			if (!pWKey)
				goto EXIT;

			// Load File to Compress & Encrypt
			PathCchCombine(szFileName, MAX_PATH, g_PIB->szCD, argv[2]);
			PVOID pFile = ReadFileCW(szFileName, 0, &nFile);
			if (!pFile)
				goto EXIT;

			// allocate info structure and generate Md5 from input
			PAESIB pAes = AllocMemory(sizeof(AESIB));
			BCRYPT_ALG_HANDLE ahMd5;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahMd5, BCRYPT_MD5_ALGORITHM, 0, 0);
			nts = BCryptHash(ahMd5, 0, 0, pFile, nFile, pAes->Md5, MD5_SIZE);
			BCryptCloseAlgorithmProvider(ahMd5, 0);

			// Compress InputFile using LZ
			COMPRESSOR_HANDLE l_ch;
			nts = CreateCompressor(COMPRESS_ALGORITHM_LZMS, 0, &l_ch);
			SIZE_T nResult;
			nts = Compress(l_ch, pFile, nFile, 0, 0, &nResult);
			PVOID pCompressed = AllocMemory(nResult);
			nts = Compress(l_ch, pFile, nFile, pCompressed, nResult, &nFile);
			FreeMemory(pFile);
			CloseCompressor(l_ch);

			// Generate Random Aes128 Key
			BCRYPT_ALG_HANDLE ahRng;
			nts = BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);
			PVOID pKey = AllocMemory(AES_KEY_SIZE);
			nts = BCryptGenRandom(ahRng, pKey, AES_KEY_SIZE, 0);
			BCRYPT_ALG_HANDLE ahAes;
			nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			BCRYPT_KEY_HANDLE khKey;
			nts = BCryptGenerateSymmetricKey(ahAes, &khKey, 0, 0, pKey, AES_KEY_SIZE, 0);

			// Wrap and export AesKey
			SIZE_T nOL;
			nts = BCryptGetProperty(ahAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nOL, sizeof(SIZE_T), &nResult, 0);
			PVOID pAesObj = AllocMemory(nOL);
			BCRYPT_KEY_HANDLE khWKey;
			nts = BCryptImportKey(ahAes, 0, BCRYPT_KEY_DATA_BLOB, &khWKey, pAesObj, nOL, (PUCHAR)pWKey, AES_BLOB_SIZE, 0);
			nts = BCryptExportKey(khKey, khWKey, BCRYPT_AES_WRAP_KEY_BLOB, pAes->Key, sizeof(pAes->Key), &nResult, 0);
			nts = BCryptDestroyKey(khWKey);
			FreeMemory(pAesObj);

			// init initialization-vector and copy
			PVOID pIv = AllocMemory(16);
			nts = BCryptGenRandom(ahRng, pIv, 16, 0);
			CopyMemory(pAes->Iv, pIv, 16);
			nts = BCryptCloseAlgorithmProvider(ahRng, 0);

			// Encrypt Data
			nts = BCryptEncrypt(khKey, pCompressed, nFile, 0, pIv, 16, 0, 0, &nResult, BCRYPT_BLOCK_PADDING);
			PVOID pEncrypted = AllocMemory(nResult);
			nts = BCryptEncrypt(khKey, pCompressed, nFile, 0, pIv, 16, pEncrypted, nResult, &nFile, BCRYPT_BLOCK_PADDING);
			FreeMemory(pCompressed);
			nts = BCryptDestroyKey(khKey);
			nts = BCryptCloseAlgorithmProvider(ahAes, 0);

			// Export Data ///////////////////////////////////////////////////////////////////////////
			PathCchCombine(szFileName, MAX_PATH, g_PIB->szCD, argv[4]);

			HANDLE hFile = CreateFileW(szFileName, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS,
				(FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED), 0);
			if (hFile) {
				nts = WriteFile(hFile, pAes, sizeof(AESIB), &nResult, 0);
				nts = WriteFile(hFile, pEncrypted, nFile, &nResult, 0);
				CloseHandle(hFile);
			}
			FreeMemory(pEncrypted);
			FreeMemory(pAes);
		} else if (argc == 4) {
			// Load AesStringKey
			PWSTR szFileName = AllocMemory(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->szCD, argv[2]);
			SIZE_T nFile;
			PVOID pSKey = ReadFileCW(szFileName, 0, &nFile);
			if (!pSKey)
				goto EXIT;

			// Import AesStringKey
			BCRYPT_ALG_HANDLE ahAes;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			SIZE_T nOL, nResult;
			nts = BCryptGetProperty(ahAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nOL, sizeof(SIZE_T), &nResult, 0);
			PVOID pAesObj = AllocMemory(nOL);
			BCRYPT_KEY_HANDLE khSKey;
			nts = BCryptImportKey(ahAes, 0, BCRYPT_KEY_DATA_BLOB, &khSKey, pAesObj, nOL, (PUCHAR)pSKey, AES_BLOB_SIZE, 0);

			// Encrypt Data
			SIZE_T nLen;
			StringCchLengthW(argv[3], 0x800, &nLen);
			nLen += 1;
			nLen *= sizeof(WCHAR);
			PVOID pIv = AllocMemory(16);
			ZeroMemory(pIv, 16);

			nts = BCryptEncrypt(khSKey, argv[3], nLen, 0, pIv, 16, 0, 0, &nResult, BCRYPT_BLOCK_PADDING);
			PVOID pEncrypted = AllocMemory(nResult);
			nts = BCryptEncrypt(khSKey, argv[3], nLen, 0, pIv, 16, pEncrypted, nResult, &nFile, BCRYPT_BLOCK_PADDING);

			FreeMemory(pIv);
			nts = BCryptDestroyKey(khSKey);
			FreeMemory(pAesObj);
			nts = BCryptCloseAlgorithmProvider(ahAes, 0);

			// Encode Data to Base64 String
			PVOID pEncoded = EBase64EncodeA(pEncrypted, nFile, &nFile);
			FreeMemory(pEncrypted);
			SetConsoleTextAttribute(g_hCon, CON_SUCCESS);
			WriteConsoleA(g_hCon, pEncoded, nFile, &nResult, 0);
			WriteConsoleW(g_hCon, L"\n", 1, &nResult, 0);
			FreeMemory(pEncoded);
		} else
			fnPrintF(L"Unknown Command\n", CON_ERROR);
	} else if ((argc <= 3) || (argc >= 5)) {
		fnPrintF(L"Usage:\n"
			L"[/gk] [OutputFile]\n"
			L"\tGenerates a random Aes128 Key and exports it to the specified [OutputFile,]\n"
			L"\tthis Key is also outputed as a Base64 encoded String to Console.\n"

			L"[/ec] [InputFile] [WKeyFile] [OutputFile]\n"
			L"\tEncrypts the specified [InputFile] with Aes128Cbc using a random generated Key and Iv.\n"
			L"\tThe AesKey is then wrapped with the imported Aes128 [WKeyFile],\n"
			L"\twhich is then exported with the encrypted Data and a Md5 Checksum to the [OutputFile].\n"
			L"[/ec] [KeyFile] [Text]\n"
			L"\tEncrypts the [Text] with Aes128Cbc using the Key imported from [KeyFile]\n"
			L"\tand outputs the Ciphertext as an Base64 encoded String to the Console.\n\n"

			L"[/pa] [_riftExe]\n"
			L"\tFinalizes the [_riftExe] by patching in the proper internal Data.\n"
			L"\tThis has to be done externaly as it is dependent on the module itself.\n",
			CON_ERROR);
	}

EXIT:
	SetConsoleTextAttribute(g_hCon, csbi.wAttributes);
	FreeMemory(g_pBuf);

	return 0;
}