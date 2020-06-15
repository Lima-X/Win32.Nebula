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

#include <Windows.h>
#pragma comment(lib, "bcrypt.lib")
#include <bcrypt.h>
#pragma comment(lib, "cabinet.lib")
#include <compressapi.h>
#pragma comment(lib, "pathcch.lib")
#include <PathCch.h>
#include <strsafe.h>

#include "..\_rift\_rift_shared.h"

static HANDLE g_hCon;
static PVOID  g_pBuf;

BOOL WriteFileCW(
	_In_     PCWSTR pFileName,
	_In_opt_ DWORD  dwFileAttribute,
	_In_     PVOID  pBuffer,
	_In_     SIZE_T nBuffer
) {
	if (!dwFileAttribute)
		dwFileAttribute = FILE_ATTRIBUTE_NORMAL;

	HANDLE hFile = CreateFileW(pFileName, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, dwFileAttribute, 0);
	if (hFile) {
		SIZE_T nWritten;
		BOOL bT = WriteFile(hFile, pBuffer, nBuffer, &nWritten, 0);
		CloseHandle(hFile);

		return bT;
	} else
		return FALSE;
}

PVOID ReadFileCW(
	_In_     PCWSTR  szFileName,
	_In_opt_ DWORD   dwFileAttribute,
	_Out_    PSIZE_T nFileSize
) {
	if (!dwFileAttribute)
		dwFileAttribute = FILE_ATTRIBUTE_NORMAL;

	PVOID pRet = 0;
	HANDLE hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, dwFileAttribute, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	LARGE_INTEGER liFS;
	BOOL bT = GetFileSizeEx(hFile, &liFS);
	if (!bT || (liFS.HighPart || !liFS.LowPart))
		goto EXIT;

	PVOID pFile = AllocMemory(liFS.LowPart);
	if (!pFile)
		goto EXIT;

	bT = ReadFile(hFile, pFile, liFS.LowPart, nFileSize, 0);
	if (!bT) {
		FreeMemory(pFile);
		goto EXIT;
	}

	pRet = pFile;
EXIT:
	CloseHandle(hFile);
	return pRet;
}

PVOID GetSection(
	_In_  PVOID   pBuffer,
	_In_  PCSTR   szSection,
	_Out_ PSIZE_T nSection
) {
	// Get Nt Headers
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pBuffer + ((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	// Find Section
	for (UINT8 i = 0; i < pFHdr->NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((PTR)pOHdr + (PTR)pFHdr->SizeOfOptionalHeader) + i);
		BOOLEAN bFlag = TRUE;
		for (UINT8 j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
			if (pSHdr->Name[j] != szSection[j]) {
				bFlag = FALSE;
				break;
			}
		} if (bFlag) {
			*nSection = pSHdr->SizeOfRawData;
			return (PTR)pBuffer + (PTR)pSHdr->PointerToRawData;
		}
	}

	return 0;
}

// shitty debug/info print function
BOOL fnPrintF(PCWSTR pText, WORD wAttribute, ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);

	DWORD nBufLen;
	StringCchVPrintfW((STRSAFE_LPWSTR)g_pBuf, 0x800, pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)g_pBuf, 0x800, (PUINT32)&nBufLen);
	SetConsoleTextAttribute(g_hCon, wAttribute);
	WriteConsoleW(g_hCon, g_pBuf, nBufLen, &nBufLen, 0);

	va_end(vaArg);
	return nBufLen;
}

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
	g_pBuf = AllocMemory(0x800 * sizeof(WCHAR), 0);
	// Safe CMD
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(g_hCon, &csbi);

	if (!(argc >= 3) && !(argc <= 5)) {
		fnPrintF(L"Usage:\n"
			L"[/gk] [OutputFile]\n"
			L"\tGenerates a random Aes128 Key and exports it to the specified [OutputFile,]\n"
			L"\tthis Key is also outputed as a Base64 encoded String to Console.\n"

			L"[/ec] [InputFile] [WKeyFile] [OutputFile]\n"
			L"\tEncrypts the specified [InputFile] with Aes128Cbc using a random generated Key and IV.\n"
		    L"\tThe AesKey is then wrapped with the imported Aes128 [WKeyFile],\n"
			L"\twhich is then exported with the encrypted Data and a Md5 Checksum to the [OutputFile].\n"
			L"[/ec] [KeyFile] [Text]\n"
			L"\tEncrypts the [Text] with Aes128Cbc using the Key imported from [KeyFile]\n"
			L"\tand outputs the Ciphertext as an Base64 encoded String to the Console.\n\n"

			L"[/pa] [_riftExe]\n"
			L"\tFinalizes the [_riftExe] by patching in the proper internal Data.\n"
			L"\tThis es to be done externaly as it is dependent on the module itself.\n"
			, CON_WARNING);
	} else if (argc ==  3) {
		if (!lstrcmpW(argv[1], L"/gk")) {
			BCRYPT_ALG_HANDLE ahAes, ahRng;
			NTSTATUS status = BCryptOpenAlgorithmProvider(&ahAes, BCRYPT_AES_ALGORITHM, 0, 0);
			status = BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);

			// Generate Random Aes128 Key
			PBYTE pKey = AllocMemory(AES_KEY_SIZE);
			status = BCryptGenRandom(ahRng, pKey, AES_KEY_SIZE, 0);
			status = BCryptCloseAlgorithmProvider(ahRng, 0);
			BCRYPT_KEY_HANDLE khAes;
			status = BCryptGenerateSymmetricKey(ahAes, &khAes, 0, 0, pKey, AES_KEY_SIZE, 0);
			FreeMemory(pKey);

			// Export Aes Blob
			SIZE_T nResult;
			PVOID pKeyE = AllocMemory(AES_BLOB_SIZE);
			status = BCryptExportKey(khAes, 0, BCRYPT_KEY_DATA_BLOB, pKeyE, AES_BLOB_SIZE, &nResult, 0);
			status = BCryptDestroyKey(khAes);
			BCryptCloseAlgorithmProvider(ahAes, 0);

			// Save Aes Blob
			PWSTR pFileName = AllocMemory(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(pFileName, MAX_PATH, g_PIB->szCD, argv[2]);
			status = WriteFileCW(pFileName, 0, pKeyE, AES_BLOB_SIZE);
			FreeMemory(pFileName);
			FreeMemory(pKeyE);
		} else if (!lstrcmpW(argv[1], L"/pa")) {
			// Load Executable/Image
			PWSTR pFileName = AllocMemory(MAX_PATH * sizeof(WCHAR));
			PathCchCombine(pFileName, MAX_PATH, g_PIB->szCD, argv[2]);
			SIZE_T nFile;
			PVOID pFile = ReadFileCW(pFileName, 0, &nFile);
			if (!pFile)
				goto exit;

			// Find Code/Text -Section
			SIZE_T nSection;
			CONST BYTE bCodeSeg[] = { '.', 't', 'e', 'x', 't', 0, 0, 0 };
			PVOID pCodeSeg = GetSection(pFile, bCodeSeg, &nSection);

			// Hash Section
			BCRYPT_ALG_HANDLE ahMd5;
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahMd5, BCRYPT_MD5_ALGORITHM, 0, 0);
			PVOID pMd5 = AllocMemory(MD5_SIZE);
			nts = BCryptHash(ahMd5, 0, 0, pCodeSeg, nSection, pMd5, MD5_SIZE);
			BCryptCloseAlgorithmProvider(ahMd5, 0);

			// Find Data location and patch
			CONST BYTE bDataSeg[] = { '.', 'd', 'a', 't', 'a', 0, 0, 0 };
			PVOID pDataSeg = GetSection(pFile, bDataSeg, &nSection);

			CONST BYTE bCsh[] = { // == 128-Bit/16-Byte
				'.', 't', 'e', 'x', 't', 'M', 'd', '5', 'S', 'i', 'g',
				0, 0, 0, 0, 0
			};
			for (UINT i = 0; i < (PTR)pDataSeg + nSection; i++) {
				BOOLEAN bFlag = TRUE;
				for (UINT8 j = 0; j < MD5_SIZE; j++) {
					if (((PBYTE)pDataSeg)[i + j] != bCsh[j]) {
						bFlag = FALSE;
						break;
					}
				} if (bFlag) {
					CopyMemory((PTR)pDataSeg + i, pMd5, MD5_SIZE);
					break;
				}
			}


		} else
			fnPrintF(L"Unknown Command", CON_ERROR);
	} if (argc == 4) {
		// Get Full Path of Wrap Key / Import it ///////////////////////////////////////////
		PWSTR szFilePath = AllocMemory(MAX_PATH * sizeof(WCHAR), 0);
		CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH * sizeof(WCHAR));
		PathCchAppend(szFilePath, MAX_PATH, L"..\\RIFTWKEY");
		HANDLE hWrapBlob = CreateFileW(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		LARGE_INTEGER liFS;
		BOOL status = GetFileSizeEx(hWrapBlob, &liFS);
		PVOID pWrapBlob = AllocMemory(liFS.LowPart, 0);
		DWORD dwRead;
		status = ReadFile(hWrapBlob, pWrapBlob, liFS.LowPart, &dwRead, 0);
		CloseHandle(hWrapBlob);

		if (!lstrcmpW(argv[1], L"/en")) {
			// Get Full Path of InputFile Parameter / Import it ////////////////////////////////////
			CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH);
			PathCchAppend(szFilePath, MAX_PATH, argv[2]);
			HANDLE hInputFile = CreateFileW(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			status = GetFileSizeEx(hInputFile, &liFS);
			PVOID pInputFile = AllocMemory(liFS.LowPart, 0);
			SIZE_T nInputFile;
			status = ReadFile(hInputFile, pInputFile, liFS.LowPart, &nInputFile, 0);
			CloseHandle(hInputFile);

			// allocate info structure and generate crc from input //////////////////////////////////////
			PAESEX pAes = (PAESEX)AllocMemory(sizeof(AESEX), 0);
			EMd5HashBegin();
			EMd5HashData(pAes->MD5, pInputFile, nInputFile);
			EMd5HashEnd();

			// allocate LZMS compressor ///////////////////////////////////////////////////////////////////
			COMPRESSOR_HANDLE l_ch;
			status = CreateCompressor(COMPRESS_ALGORITHM_LZMS, 0, &l_ch);
			if (!status) {
				fnPrintF(L"Couldn't create compressor\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			}

			// calculate compressed filesize and allocate buffer
			SIZE_T nCompressed;
			PBYTE pCompressed = 0;
			status = Compress(l_ch, pInputFile, nInputFile, 0, 0, &nCompressed);
			if (!status) {
				DWORD dwError = GetLastError();
				if (dwError != ERROR_INSUFFICIENT_BUFFER) {
					fnPrintF(L"Couldn't compress Data\nErrorcode: 0x%08x\n", CON_ERROR);
					goto exit;
				} else {
					pCompressed = (PBYTE)AllocMemory(nCompressed, 0);
					if (!pCompressed) {
						fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
						goto exit;
					}
				}
			}

			// compress File
			status = Compress(l_ch, pInputFile, nInputFile, pCompressed, nCompressed, &nCompressed);
			if (!status) {
				fnPrintF(L"Couldn't compress Data\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			} if (nCompressed > nInputFile) // <- Unlikely
				fnPrintF(L"Compressed File will be bigger the original\nThis will be updated\n", CON_WARNING);

			// Free Data
			FreeMemory(pInputFile);
			CloseCompressor(l_ch);

			// Open Algorithm Providers ///////////////////////////////////////////////////////////////////
			BCRYPT_ALG_HANDLE cahAES, cahRNG;
			status = BCryptOpenAlgorithmProvider(&cahAES, BCRYPT_AES_ALGORITHM, 0, 0);
			status = BCryptOpenAlgorithmProvider(&cahRNG, BCRYPT_RNG_ALGORITHM, 0, 0);

			// Generate Key From Data
			PBYTE pKey = (PBYTE)AllocMemory(AES_KEY_SIZE, 0);
			status = BCryptGenRandom(cahRNG, pKey, AES_KEY_SIZE, 0);

			// Allocate key objects, generate AES key's and export them
			SIZE_T nResult;
			DWORD dwBL;
			BCRYPT_KEY_HANDLE ckhAES, ckhWrap;
			status = BCryptGetProperty(cahAES, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwBL, sizeof(DWORD), &nResult, 0);
			PBYTE pAesObj = (PBYTE)AllocMemory(dwBL, 0);
			status = BCryptImportKey(cahAES, 0, BCRYPT_KEY_DATA_BLOB, &ckhWrap, pAesObj, dwBL, (PUCHAR)pWrapBlob, AES_BLOB_SIZE, 0);
			status = BCryptGenerateSymmetricKey(cahAES, &ckhAES, 0, 0, pKey, AES_KEY_SIZE, 0);
			status = BCryptExportKey(ckhAES, ckhWrap, BCRYPT_AES_WRAP_KEY_BLOB, pAes->KEY, sizeof(pAes->KEY), &nResult, 0);
			status = BCryptDestroyKey(ckhWrap);

			// init initialization-vector and copy
			status = BCryptGenRandom(cahRNG, pAes->IV, 16, 0);
			PBYTE pIV = (PBYTE)AllocMemory(16, 0);
			CopyMemory(pIV, pAes->IV, 16);

			// Encrypt Data
			status = BCryptEncrypt(ckhAES, (PBYTE)pCompressed, nCompressed, 0, pIV, 16, 0, 0, &nResult, BCRYPT_BLOCK_PADDING);
			PBYTE pEncrypted = (PBYTE)AllocMemory(nResult, 0);
			status = BCryptEncrypt(ckhAES, (PBYTE)pCompressed, nCompressed, 0, pIV, 16, pEncrypted, nResult, &nResult, BCRYPT_BLOCK_PADDING);

			FreeMemory(pCompressed);
			status = BCryptDestroyKey(ckhAES);
			status = BCryptCloseAlgorithmProvider(cahAES, 0);
			status = BCryptCloseAlgorithmProvider(cahRNG, 0);

			// Export Data ///////////////////////////////////////////////////////////////////////////
			DWORD dwWritten;
			CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH);
			PathCchAppend(szFilePath, MAX_PATH, argv[3]);
			hInputFile = CreateFileW(szFilePath, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED), 0);
			if (hInputFile) {
				status = WriteFile(hInputFile, pAes, sizeof(AESEX), &dwWritten, 0);
				status = WriteFile(hInputFile, pEncrypted, nResult, &dwWritten, 0);
				CloseHandle(hInputFile);
			}
			FreeMemory(pEncrypted);
			FreeMemory(pAes);
		} else
		fnPrintF(L"Unknown Command\n", CON_ERROR);

		FreeMemory(szFilePath);
	}

exit:
	SetConsoleTextAttribute(g_hCon, csbi.wAttributes);
	FreeMemory(g_pBuf);

	return 0;
}