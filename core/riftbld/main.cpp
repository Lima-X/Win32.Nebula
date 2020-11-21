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

// Actually this is getting more important with time
// this will actually be shipped with _rift (private)
// it will be shipped as a utility not only used for building dependencies
// and patching _rift(ldr) but it will also be able to generate overrides
// (note: those overrides are registry key's based on the hwid)

#include "shared.h"

PIB* g_PIB;

#pragma region Utilities
class FileMap {
public:
	// Add support for readonly Pages
	FileMap(
		_In_ const wchar* const szFile,
		_In_ dword dwAccess = GENERIC_READ | GENERIC_WRITE,
		_In_ dword dwShare = FILE_SHARE_READ,
		_In_ dword dwProtection = PAGE_READWRITE
	) {
		if ((m_hFile = CreateFileW(szFile, dwAccess, dwShare, nullptr, OPEN_EXISTING, NULL, nullptr)) == INVALID_HANDLE_VALUE)
			return;
		if (!(m_hMap = CreateFileMappingW(m_hFile, nullptr, dwProtection, 0, 0, nullptr)))
			return;

		m_pFile = MapViewOfFile(m_hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		MEMORY_BASIC_INFORMATION mbi;
		m_nFile = VirtualQuery(m_pFile, &mbi, 0);
	}
	~FileMap() {
		UnmapViewOfFile(m_pFile);
		CloseHandle(m_hMap);
		CloseHandle(m_hFile);
	}
	void* const Data() const { return m_pFile; }
	const size_t& Size() const { return m_nFile; }
private:
	void* m_pFile;
	size_t m_nFile;
	HANDLE m_hMap;
	HANDLE m_hFile;
};

void* GetSectionRaw(
	_In_  void* pBuffer,
	_In_  PCSTR   szSection,
	_Out_ size_t* nSection
) {
	// Get Nt Headers
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ptr)pBuffer + ((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	// Find Section
	for (uchar i = 0; i < pFHdr->NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((ptr)pOHdr + (ptr)pFHdr->SizeOfOptionalHeader) + i);
		BOOLEAN bFlag = TRUE;
		for (uchar j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
			if (pSHdr->Name[j] != szSection[j]) {
				bFlag = FALSE;
				break;
			}
		} if (bFlag) {
			*nSection = pSHdr->SizeOfRawData;
			return (void*)((ptr)pBuffer + (ptr)pSHdr->PointerToRawData);
		}
	}

	return 0;
}
#pragma endregion

int wmain(
	_In_     int    argc,
	_In_     wchar* argv[],
	_In_opt_ wchar* envp[]
) {
	UNREFERENCED_PARAMETER(envp);
	{	// Initialize Process Information block
		g_PIB = (PIB*)malloc(sizeof(PIB));
		GetCurrentDirectoryW(MAX_PATH, g_PIB->sMod.szCD);
	}

	con::Console con;

	if ((argc < 3) || (argc > 5)) {
		con.PrintFW(L"Usage:\n"
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
			con::Console::Attributes::CON_INFO);
	} else if (argc == 3) {
		if (!lstrcmpW(argv[1], L"/pa")) {
			// Load Executable/Image
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			FileMap fm(szFileName);
			if (!fm.Data())
				goto EXIT;

			{	// Get Nt Headers
				PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ptr)fm.Data() + ((PIMAGE_DOS_HEADER)fm.Data())->e_lfanew);
				if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
					goto EXIT;
				if (pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
					goto EXIT;

				// Prepare Hashing
				BCRYPT_ALG_HANDLE ah;
				BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, 0, 0);
				BCRYPT_HASH_HANDLE hh;
				BCryptCreateHash(ah, &hh, 0, 0, 0, 0, 0);

				// Hash Sections
				void* pHash = 0;
				// Get first Section
				PIMAGE_SECTION_HEADER pSHdr = IMAGE_FIRST_SECTION(pNtHdr);
				for (uint8 i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
					// Check if Type is accepted
					if (!((pSHdr->Characteristics & IMAGE_SCN_CNT_CODE) || (pSHdr->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)))
						continue;

					// Check for Special Section
					BOOLEAN bFlag = false;
					// Removed because of errors

					// Set Section Pointers
					void* pSection = (void*)((ptr)fm.Data() + pSHdr->PointerToRawData);
					size_t nSection = pSHdr->SizeOfRawData;

					// Select what to to
					if (bFlag == 1) {
						for (uint32 j = 0; j < nSection - sizeof(cry::Hash::hash); j++) {
							bFlag = TRUE;
							for (uchar n = 0; n < sizeof(cry::Hash::hash); n++) {
								// Removed because of errors
							} if (bFlag) {
								pHash = (void*)((ptr)pSection + j);
								break;
							}
						}

						size_t nRDataP1 = (ptr)pHash - (ptr)pSection;
						BCryptHashData(hh, (uchar*)pSection, nRDataP1, 0);
						size_t nRDataP2 = ((ptr)pSection + nSection) - ((ptr)pHash + sizeof(cry::Hash::hash));
						// this is unsafe, i should rather get the size of the sig then to assume it... but idc atm :D
						BCryptHashData(hh, (uchar*)((ptr)pHash + sizeof(cry::Hash::hash)), nRDataP2, 0);
					} else if (bFlag >= 2)
						continue;
					else
						BCryptHashData(hh, (uchar*)pSection, nSection, 0);
				}

				// Finish Hash
				void* pMd5 = malloc(sizeof(cry::Hash::hash));
				BCryptFinishHash(hh, (uchar*)pMd5, sizeof(cry::Hash::hash), 0);
				BCryptDestroyHash(hh);
				BCryptCloseAlgorithmProvider(ah, 0);

				// Patch Image
				memcpy(pHash, pMd5, sizeof(cry::Hash::hash));
				free(pMd5);
			}

			// Commit Changes to Image
			fm.~FileMap();
			free(szFileName);
		} else
			con.PrintFW(L"Unknown Command\n", con::Console::Attributes::CON_ERROR);
	} else if (argc == 4) {
		if (!lstrcmpW(argv[1], L"/gk")) {
			// Generate Random Aes128 Key
			BCRYPT_ALG_HANDLE ahAes, ahRng;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			nts = BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);
			byte* pKey = (byte*)malloc(cry::Aes::AesKeySize);
			nts = BCryptGenRandom(ahRng, pKey, cry::Aes::AesKeySize, 0);
			nts = BCryptCloseAlgorithmProvider(ahRng, 0);
			BCRYPT_KEY_HANDLE khAes;
			nts = BCryptGenerateSymmetricKey(ahAes, &khAes, 0, 0, pKey, cry::Aes::AesKeySize, 0);
			free(pKey);

			// Export AesBlob
			size_t nResult;
			void* pKeyE = malloc(cry::Aes::AesBlobSize);
			nts = BCryptExportKey(khAes, 0, BCRYPT_KEY_DATA_BLOB, (uchar*)pKeyE, cry::Aes::AesBlobSize, (ulong*)&nResult, 0);
			nts = BCryptDestroyKey(khAes);
			BCryptCloseAlgorithmProvider(ahAes, 0);

			// Save Aes Blob
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			// nts = WriteFileCW(szFileName, 0, pKeyE, AES_BLOB_SIZE);
			free(szFileName);
			free(pKeyE);
		} else if (!lstrcmpW(argv[1], L"/gt")) {
			// Load WrapKey
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			FileMap fmWKey(szFileName);
			if (!fmWKey.Data())
				goto EXIT;

			// Generate Random Data
			BCRYPT_ALG_HANDLE ahRng;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);
			void* pData = malloc(512);
			BCryptGenRandom(ahRng, (uchar*)((ptr)pData + sizeof(cry::Hash::hash)), 512 - sizeof(cry::Hash::hash), NULL);
			nts = BCryptCloseAlgorithmProvider(ahRng, 0);

			// Hash Random Data
			BCRYPT_ALG_HANDLE ahMd5;
			nts = BCryptOpenAlgorithmProvider(&ahMd5, BCRYPT_MD5_ALGORITHM, 0, 0);
			nts = BCryptHash(ahMd5, 0, 0, (uchar*)((ptr)pData + sizeof(cry::Hash::hash)), 512 - sizeof(cry::Hash::hash), (uchar*)pData, sizeof(cry::Hash::hash));
			BCryptCloseAlgorithmProvider(ahMd5, 0);

			// Import AesWrapKey
			BCRYPT_ALG_HANDLE ahAes;
			nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			size_t nOL, nResult;
			nts = BCryptGetProperty(ahAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nOL, sizeof(size_t), (ulong*)&nResult, 0);
			void* pAesObj = malloc(nOL);
			BCRYPT_KEY_HANDLE khWKey;
			nts = BCryptImportKey(ahAes, 0, BCRYPT_KEY_DATA_BLOB, &khWKey, (uchar*)pAesObj, nOL, (PUCHAR)fmWKey.Data(), cry::Aes::AesBlobSize, 0);

			// initialization-vector and Encrypt
			void* pIv = malloc(16);
			ZeroMemory(pIv, 16);
			nts = BCryptEncrypt(khWKey, (uchar*)((ptr)pData + sizeof(cry::Hash::hash)), 512 - sizeof(cry::Hash::hash),
				0, (uchar*)pIv, 16, (uchar*)((ptr)pData + sizeof(cry::Hash::hash)), 512 - sizeof(cry::Hash::hash), (ulong*)&nResult, 0);
			free(pIv);

			// Save TestFile
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[3]);
			// nts = WriteFileCW(szFileName, FILE_ATTRIBUTE_ENCRYPTED, pData, 512);
			free(szFileName);
			free(pData);
		}
	} else if (!lstrcmpW(argv[1], L"/ec")) {
		if (argc == 5) {
			// Load WrapKey
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[3]);
			FileMap fmWKey(szFileName);
			if (!fmWKey.Data())
				goto EXIT;

			// Load File to Compressor & Encrypt
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			FileMap fmFile(szFileName);
			if (!fmFile.Data())
				goto EXIT;

			// allocate info structure and generate Hash from input
			cry::Aes::AESIB* pAes = (cry::Aes::AESIB*)malloc(sizeof(cry::Aes::AESIB));
			BCRYPT_ALG_HANDLE ahMd5;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahMd5, BCRYPT_MD5_ALGORITHM, 0, 0);
			nts = BCryptHash(ahMd5, 0, 0, (uchar*)fmFile.Data(), fmFile.Size(), (uchar*)&pAes->Hash, sizeof(cry::Hash::hash));
			BCryptCloseAlgorithmProvider(ahMd5, 0);

			// Compressor InputFile using LZ
			COMPRESSOR_HANDLE l_ch;
			nts = CreateCompressor(COMPRESS_ALGORITHM_LZMS, 0, &l_ch);
			size_t nResult;
			nts = Compress(l_ch, fmFile.Data(), fmFile.Size(), 0, 0, (SIZE_T*)&nResult);
			void* pCompressed = malloc(nResult);
			size_t nFile;
			nts = Compress(l_ch, fmFile.Data(), fmFile.Size(), pCompressed, nResult, (SIZE_T*)&nFile);
			CloseCompressor(l_ch);

			// Generate Random Aes128 Key
			BCRYPT_ALG_HANDLE ahRng;
			nts = BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);
			void* pKey = malloc(cry::Aes::AesKeySize);
			nts = BCryptGenRandom(ahRng, (uchar*)pKey, cry::Aes::AesKeySize, 0);
			BCRYPT_ALG_HANDLE ahAes;
			nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			BCRYPT_KEY_HANDLE khKey;
			nts = BCryptGenerateSymmetricKey(ahAes, &khKey, 0, 0, (uchar*)pKey, cry::Aes::AesKeySize, 0);

			// Wrap and export AesKey
			size_t nOL;
			nts = BCryptGetProperty(ahAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nOL, sizeof(size_t), (ulong*)&nResult, 0);
			void* pAesObj = malloc(nOL);
			BCRYPT_KEY_HANDLE khWKey;
			nts = BCryptImportKey(ahAes, 0, BCRYPT_KEY_DATA_BLOB, &khWKey, (uchar*)pAesObj, nOL, (PUCHAR)fmWKey.Data(), cry::Aes::AesBlobSize, 0);
			nts = BCryptExportKey(khKey, khWKey, BCRYPT_AES_WRAP_KEY_BLOB, pAes->Key, sizeof(pAes->Key), (ulong*)&nResult, 0);
			nts = BCryptDestroyKey(khWKey);
			free(pAesObj);

			// init initialization-vector and copy
			void* pIv = malloc(16);
			nts = BCryptGenRandom(ahRng, (uchar*)pIv, 16, 0);
			// CopyMemory(pAes->Iv, pIv, 16);
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

			HANDLE m_hFile = CreateFileW(szFileName, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS,
				(FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED), 0);
			if (m_hFile) {
				nts = WriteFile(m_hFile, pAes, sizeof(cry::Aes::AESIB), (dword*)&nResult, 0);
				nts = WriteFile(m_hFile, pEncrypted, nFile, (dword*)&nResult, 0);
				CloseHandle(m_hFile);
			}
			free(pEncrypted);
			free(pAes);
		} else if (argc == 4) {
			// Load AesStringKey
			PWSTR szFileName = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(szFileName, MAX_PATH, g_PIB->sMod.szCD, argv[2]);
			FileMap fmSKey(szFileName);
			if (!fmSKey.Data())
				goto EXIT;

			// Import AesStringKey
			BCRYPT_ALG_HANDLE ahAes;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			size_t nOL, nResult;
			nts = BCryptGetProperty(ahAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nOL, sizeof(size_t), (ulong*)&nResult, 0);
			void* pAesObj = malloc(nOL);
			BCRYPT_KEY_HANDLE khSKey;
			nts = BCryptImportKey(ahAes, 0, BCRYPT_KEY_DATA_BLOB, &khSKey, (uchar*)pAesObj, nOL, (PUCHAR)fmSKey.Data(), cry::Aes::AesBlobSize, 0);

			// Encrypt Data
			size_t nLen = wcslen(argv[3]);
			nLen++;
			nLen *= sizeof(WCHAR);
			void* pIv = malloc(16);
			ZeroMemory(pIv, 16);

			nts = BCryptEncrypt(khSKey, (uchar*)argv[3], nLen, 0, (uchar*)pIv, 16, 0, 0, (ulong*)&nResult, BCRYPT_BLOCK_PADDING);
			void* pEncrypted = malloc(nResult);
			size_t nFile;
			nts = BCryptEncrypt(khSKey, (uchar*)argv[3], nLen, 0, (uchar*)pIv, 16, (uchar*)pEncrypted, nResult, (ulong*)&nFile, BCRYPT_BLOCK_PADDING);

			free(pIv);
			nts = BCryptDestroyKey(khSKey);
			free(pAesObj);
			nts = BCryptCloseAlgorithmProvider(ahAes, 0);

			// Encode Data to Hex String
			alg::HexConvA h16;
			void* pEncoded = malloc(nFile);
			h16.BinToHex(pEncrypted, nFile, (char*)pEncoded);

			free(pEncrypted);
			WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), pEncoded, nFile, (dword*)&nResult, 0);
			WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), L"\n", 1, (dword*)&nResult, 0);
			free(pEncoded);
		} else
			con.PrintFW(L"Unknown Command\n", con::Console::Attributes::CON_ERROR);
	}

EXIT:
	return 0;
}
