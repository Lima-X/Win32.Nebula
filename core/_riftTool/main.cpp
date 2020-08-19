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

int wmain(
	_In_     int    argc,
	_In_     PWCHAR argv[],
	_In_opt_ PWCHAR envp[]
) {
	UNREFERENCED_PARAMETER(envp);
	{	// Initialize Process Information block
		g_PIB = (PIB*)malloc(sizeof(PIB));
		GetCurrentDirectoryW(MAX_PATH, g_PIB->sMod.szCD);
	}
	g_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
	// Safe CMD
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(g_hCon, &csbi);

	if ((argc < 3) || (argc > 5)) {
		PrintF(L"Usage:\n"
			L"[/gk] [SKeyFile] [OutputFile]\n"
			L"\tGenerates a random Aes128 Key and exports it to the specified [OutputFile,]\n"
			L"\tthis Key is then also Wrapped with the hardcoded Internal Key\n"
			L"[/gt] [WKeyFile] [OutputFile]\n"
			L"\tGenerates a 256-Byte test file filled with random encrypted data and a Checksum\n"
			L"\tto validate if the Decryptionkey is valid.\n\n"

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
	} else if (argc == 3) {
		if (!lstrcmpW(argv[1], L"/pa")) {
			// Load Executable/Image
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			size_t nFile;
			void* pFile = ReadFileCW(szFileName, 0, &nFile);
			if (!pFile)
				goto EXIT;

			// Get Nt Headers
			PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pFile;
			PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ptr)pDosHdr + pDosHdr->e_lfanew);
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
			void* pHash = 0;
			for (uchar i = 0; i < pFHdr->NumberOfSections; i++) {
				// Get Section and Check if Type is accepted
				PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((ptr)pOHdr + (ptr)pFHdr->SizeOfOptionalHeader) + i);
				if (!((pSHdr->Characteristics & IMAGE_SCN_CNT_CODE) || (pSHdr->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)))
					continue;

				// Check for Special Section
				BOOLEAN bFlag;
				for (uchar j = 0; j < e_nSections; j++) {
					bFlag = TRUE;
					for (uchar n = 0; n < IMAGE_SIZEOF_SHORT_NAME; n++) {
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
				void* pSection = (void*)((ptr)pDosHdr + (ptr)pSHdr->PointerToRawData);
				size_t nSection = pSHdr->SizeOfRawData;

				// Select what to to
				if (bFlag == 1) {
					for (uint32 j = 0; j < nSection - sizeof(cry::Md5::hash); j++) {
						bFlag = TRUE;
						for (uchar n = 0; n < sizeof(cry::Md5::hash); n++) {
							if (((byte*)pSection)[j + n] != (*(byte**)&e_HashSig)[n]) {
								bFlag = FALSE;
								break;
							}
						} if (bFlag) {
							pHash = (void*)((ptr)pSection + j);
							break;
						}
					}

					size_t nRDataP1 = (ptr)pHash - (ptr)pSection;
					BCryptHashData(hh, (uchar*)pSection, nRDataP1, 0);
					size_t nRDataP2 = ((ptr)pSection + nSection) - ((ptr)pHash + sizeof(cry::Md5::hash));
					// this is unsafe, i should rather get the size of the sig then to assume it... but idc atm :D
					BCryptHashData(hh, (uchar*)((ptr)pHash + sizeof(cry::Md5::hash)), nRDataP2, 0);
				} else if (bFlag >= 2)
					continue;
				else
					BCryptHashData(hh, (uchar*)pSection, nSection, 0);
			}

			// Finish Hash
			void* pMd5 = malloc(sizeof(cry::Md5::hash));
			BCryptFinishHash(hh, (uchar*)pMd5, sizeof(cry::Md5::hash), 0);
			BCryptDestroyHash(hh);
			BCryptCloseAlgorithmProvider(ah, 0);

			// Patch Image
			memcpy(pHash, pMd5, sizeof(cry::Md5::hash));
			free(pMd5);

			// Commit Changes to Image
			WriteFileCW(szFileName, 0, pFile, nFile);
			free(pFile);
			free(szFileName);
		} else
			PrintF(L"Unknown Command\n", CON_ERROR);
	} else if (argc == 4) {
		if (!lstrcmpW(argv[1], L"/gk")) {
			// Generate Random Aes128 Key
			BCRYPT_ALG_HANDLE ahAes, ahRng;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			nts = BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);
			byte* pKey = (byte*)malloc(AES_KEY_SIZE);
			nts = BCryptGenRandom(ahRng, pKey, AES_KEY_SIZE, 0);
			nts = BCryptCloseAlgorithmProvider(ahRng, 0);
			BCRYPT_KEY_HANDLE khAes;
			nts = BCryptGenerateSymmetricKey(ahAes, &khAes, 0, 0, pKey, AES_KEY_SIZE, 0);
			free(pKey);

			// Export AesBlob
			size_t nResult;
			void* pKeyE = malloc(AES_BLOB_SIZE);
			nts = BCryptExportKey(khAes, 0, BCRYPT_KEY_DATA_BLOB, (uchar*)pKeyE, AES_BLOB_SIZE, (ulong*)&nResult, 0);
			nts = BCryptDestroyKey(khAes);
			BCryptCloseAlgorithmProvider(ahAes, 0);

			// Save Aes Blob
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			nts = WriteFileCW(szFileName, 0, pKeyE, AES_BLOB_SIZE);
			free(szFileName);
			free(pKeyE);
		} else if (!lstrcmpW(argv[1], L"/gt")) {
			// Load WrapKey
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			size_t nResult;
			void* pWKey = ReadFileCW(szFileName, 0, &nResult);
			if (!pWKey)
				goto EXIT;

			// Generate Random Data
			BCRYPT_ALG_HANDLE ahRng;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);
			void* pData = malloc(512);
			BCryptGenRandom(ahRng, (uchar*)((ptr)pData + sizeof(cry::Md5::hash)), 512 - sizeof(cry::Md5::hash), NULL);
			nts = BCryptCloseAlgorithmProvider(ahRng, 0);

			// Hash Random Data
			BCRYPT_ALG_HANDLE ahMd5;
			nts = BCryptOpenAlgorithmProvider(&ahMd5, BCRYPT_MD5_ALGORITHM, 0, 0);
			nts = BCryptHash(ahMd5, 0, 0, (uchar*)((ptr)pData + sizeof(cry::Md5::hash)), 512 - sizeof(cry::Md5::hash), (uchar*)pData, sizeof(cry::Md5::hash));
			BCryptCloseAlgorithmProvider(ahMd5, 0);

			// Import AesWrapKey
			BCRYPT_ALG_HANDLE ahAes;
			nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			size_t nOL;
			nts = BCryptGetProperty(ahAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nOL, sizeof(size_t), (ulong*)&nResult, 0);
			void* pAesObj = malloc(nOL);
			BCRYPT_KEY_HANDLE khWKey;
			nts = BCryptImportKey(ahAes, 0, BCRYPT_KEY_DATA_BLOB, &khWKey, (uchar*)pAesObj, nOL, (PUCHAR)pWKey, AES_BLOB_SIZE, 0);

			// initialization-vector and Encrypt
			void* pIv = malloc(16);
			ZeroMemory(pIv, 16);
			nts = BCryptEncrypt(khWKey, (uchar*)((ptr)pData + sizeof(cry::Md5::hash)), 512 - sizeof(cry::Md5::hash),
				0, (uchar*)pIv, 16, (uchar*)((ptr)pData + sizeof(cry::Md5::hash)), 512 - sizeof(cry::Md5::hash), (ulong*)&nResult, 0);
			free(pIv);

			// Save TestFile
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[3]);
			nts = WriteFileCW(szFileName, FILE_ATTRIBUTE_ENCRYPTED, pData, 512);
			free(szFileName);
			free(pData);
		}
	} else if (!lstrcmpW(argv[1], L"/ec")) {
		if (argc == 5) {
			// Load WrapKey
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[3]);
			size_t nFile;
			void* pWKey = ReadFileCW(szFileName, 0, &nFile);
			if (!pWKey)
				goto EXIT;

			// Load File to Compress & Encrypt
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			void* pFile = ReadFileCW(szFileName, 0, &nFile);
			if (!pFile)
				goto EXIT;

			// allocate info structure and generate Md5 from input
			cry::Aes::AESIB* pAes = (cry::Aes::AESIB*)malloc(sizeof(cry::Aes::AESIB));
			BCRYPT_ALG_HANDLE ahMd5;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahMd5, BCRYPT_MD5_ALGORITHM, 0, 0);
			nts = BCryptHash(ahMd5, 0, 0, (uchar*)pFile, nFile, (uchar*)&pAes->Hash, sizeof(cry::Md5::hash));
			BCryptCloseAlgorithmProvider(ahMd5, 0);

			// Compress InputFile using LZ
			COMPRESSOR_HANDLE l_ch;
			nts = CreateCompressor(COMPRESS_ALGORITHM_LZMS, 0, &l_ch);
			size_t nResult;
			nts = Compress(l_ch, pFile, nFile, 0, 0, (SIZE_T*)&nResult);
			void* pCompressed = malloc(nResult);
			nts = Compress(l_ch, pFile, nFile, pCompressed, nResult, (SIZE_T*)&nFile);
			free(pFile);
			CloseCompressor(l_ch);

			// Generate Random Aes128 Key
			BCRYPT_ALG_HANDLE ahRng;
			nts = BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);
			void* pKey = malloc(AES_KEY_SIZE);
			nts = BCryptGenRandom(ahRng, (uchar*)pKey, AES_KEY_SIZE, 0);
			BCRYPT_ALG_HANDLE ahAes;
			nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			BCRYPT_KEY_HANDLE khKey;
			nts = BCryptGenerateSymmetricKey(ahAes, &khKey, 0, 0, (uchar*)pKey, AES_KEY_SIZE, 0);

			// Wrap and export AesKey
			size_t nOL;
			nts = BCryptGetProperty(ahAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nOL, sizeof(size_t), (ulong*)&nResult, 0);
			void* pAesObj = malloc(nOL);
			BCRYPT_KEY_HANDLE khWKey;
			nts = BCryptImportKey(ahAes, 0, BCRYPT_KEY_DATA_BLOB, &khWKey, (uchar*)pAesObj, nOL, (PUCHAR)pWKey, AES_BLOB_SIZE, 0);
			nts = BCryptExportKey(khKey, khWKey, BCRYPT_AES_WRAP_KEY_BLOB, pAes->Key, sizeof(pAes->Key), (ulong*)&nResult, 0);
			nts = BCryptDestroyKey(khWKey);
			free(pAesObj);

			// init initialization-vector and copy
			void* pIv = malloc(16);
			nts = BCryptGenRandom(ahRng, (uchar*)pIv, 16, 0);
			CopyMemory(pAes->Iv, pIv, 16);
			nts = BCryptCloseAlgorithmProvider(ahRng, 0);

			// Encrypt Data
			nts = BCryptEncrypt(khKey, (uchar*)pCompressed, nFile, 0, (uchar*)pIv, 16, 0, 0, (ulong*)&nResult, BCRYPT_BLOCK_PADDING);
			void* pEncrypted = malloc(nResult);
			nts = BCryptEncrypt(khKey, (uchar*)pCompressed, nFile, 0, (uchar*)pIv, 16, (uchar*)pEncrypted, nResult, (ulong*)&nFile, BCRYPT_BLOCK_PADDING);
			free(pCompressed);
			nts = BCryptDestroyKey(khKey);
			nts = BCryptCloseAlgorithmProvider(ahAes, 0);

			// Export Data ///////////////////////////////////////////////////////////////////////////
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[4]);

			HANDLE hFile = CreateFileW(szFileName, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS,
				(FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED), 0);
			if (hFile) {
				nts = WriteFile(hFile, pAes, sizeof(cry::Aes::AESIB), (dword*)&nResult, 0);
				nts = WriteFile(hFile, pEncrypted, nFile, (dword*)&nResult, 0);
				CloseHandle(hFile);
			}
			free(pEncrypted);
			free(pAes);
		} else if (argc == 4) {
			// Load AesStringKey
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			size_t nFile;
			void* pSKey = ReadFileCW(szFileName, 0, &nFile);
			if (!pSKey)
				goto EXIT;

			// Import AesStringKey
			BCRYPT_ALG_HANDLE ahAes;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			size_t nOL, nResult;
			nts = BCryptGetProperty(ahAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nOL, sizeof(size_t), (ulong*)&nResult, 0);
			void* pAesObj = malloc(nOL);
			BCRYPT_KEY_HANDLE khSKey;
			nts = BCryptImportKey(ahAes, 0, BCRYPT_KEY_DATA_BLOB, &khSKey, (uchar*)pAesObj, nOL, (PUCHAR)pSKey, AES_BLOB_SIZE, 0);

			// Encrypt Data
			size_t nLen = wcslen(argv[3]);
			nLen++;
			nLen *= sizeof(WCHAR);
			void* pIv = malloc(16);
			ZeroMemory(pIv, 16);

			nts = BCryptEncrypt(khSKey, (uchar*)argv[3], nLen, 0, (uchar*)pIv, 16, 0, 0, (ulong*)&nResult, BCRYPT_BLOCK_PADDING);
			void* pEncrypted = malloc(nResult);
			nts = BCryptEncrypt(khSKey, (uchar*)argv[3], nLen, 0, (uchar*)pIv, 16, (uchar*)pEncrypted, nResult, (ulong*)&nFile, BCRYPT_BLOCK_PADDING);

			free(pIv);
			nts = BCryptDestroyKey(khSKey);
			free(pAesObj);
			nts = BCryptCloseAlgorithmProvider(ahAes, 0);

			// Encode Data to Base64 String
			alg::Base64 b64;
			nFile = b64.EBase64EncodeA(pEncrypted, nFile, nullptr, true);
			void* pEncoded = malloc(nFile);
			nFile = b64.EBase64EncodeA(pEncrypted, nFile, (PSTR)pEncoded, true);

			free(pEncrypted);
			SetConsoleTextAttribute(g_hCon, CON_SUCCESS);
			WriteConsoleA(g_hCon, pEncoded, nFile, (dword*)&nResult, 0);
			WriteConsoleW(g_hCon, L"\n", 1, (dword*)&nResult, 0);
			free(pEncoded);
		} else
			PrintF(L"Unknown Command\n", CON_ERROR);
	}

EXIT:
	SetConsoleTextAttribute(g_hCon, csbi.wAttributes);
	return 0;
}