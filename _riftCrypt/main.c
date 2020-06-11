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

PVOID ELoadResourceW(
	_In_  WORD    wResID,
	_In_  PCWSTR  pResType,
	_Out_ PSIZE_T nBufferSize
) {
	HRSRC hResInfo = FindResourceW(0, MAKEINTRESOURCEW(wResID), pResType);
	if (hResInfo) {
		HGLOBAL hgData = LoadResource(0, hResInfo);
		if (hgData) {
			PVOID lpBuffer = LockResource(hgData);
			if (!lpBuffer)
				return 0;

			*nBufferSize = SizeofResource(0, hResInfo);
			if (!*nBufferSize)
				return 0;

			return lpBuffer;
		}
	}

	return 0;
}
BOOL WriteFileCW(
	_In_ PCWSTR pFileName,
	_In_ PVOID  pBuffer,
	_In_ SIZE_T nBuffer
) {
	HANDLE hFile = CreateFileW(pFileName, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
	if (hFile) {
		DWORD dwT;
		BOOL bT = WriteFile(hFile, pBuffer, nBuffer, &dwT, 0);
		CloseHandle(hFile);

		return bT;
	}
	else
		return FALSE;
}

static HANDLE g_hCon;
static PVOID  g_pBuf;

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

	if ((argc != 4) && (argc != 3) && (argc != 2)) {
		fnPrintF(L"Usage: [gw] [KeyFileName]/([en/de] [InputFile] [OutputName/File])\n\n"
		         L"\t[/en] : Encrypts the specified file with AES256 in CBC mode (random KEY, pIV),\n"
		         L"\t        the encrypted file is then written to the the current directory.\n"
		         L"\t        The Application will also export the KEY, pIV, a CRC Checksum of the original\n"
		         L"\t        and internal data (for the decryption part).\n\n"
		         L"\t[/de] : Decrypts and decompresses the specified file,\n"
		         L"\t        it also validates that the decrypted content is not corrupted.\n\n"
		         L"\t[/gw] : Generates the wrap Key used to encrypt the key,\n"
		         L"\t        that is packed into the encryped data package.\n", CON_WARNING);
	} else if (argc > 1) {
		if (!lstrcmpW(argv[1], L"/gw")) {
			BCRYPT_ALG_HANDLE cahAES, cahRNG;
			NTSTATUS status = BCryptOpenAlgorithmProvider(&cahAES, BCRYPT_AES_ALGORITHM, 0, 0);
			status = BCryptOpenAlgorithmProvider(&cahRNG, BCRYPT_RNG_ALGORITHM, 0, 0);

			PBYTE pWrap = (PBYTE)HeapAlloc(g_PIB->hPH, 0, AES_KEY_SIZE);
			status = BCryptGenRandom(cahRNG, pWrap, AES_KEY_SIZE, 0);
			status = BCryptCloseAlgorithmProvider(cahRNG, 0);

			BCRYPT_KEY_HANDLE ckhWrap;
			status = BCryptGenerateSymmetricKey(cahAES, &ckhWrap, 0, 0, pWrap, AES_KEY_SIZE, 0);
			FreeMemory(pWrap);

			SIZE_T nResult;
			pWrap = (PBYTE)HeapAlloc(g_PIB->hPH, 0, AES_BLOB_SIZE);
			status = BCryptExportKey(ckhWrap, 0, BCRYPT_KEY_DATA_BLOB, pWrap, AES_BLOB_SIZE, &nResult, 0);
			status = BCryptDestroyKey(ckhWrap);
			BCryptCloseAlgorithmProvider(cahAES, 0);

			PWSTR pFilePath = (PWSTR)HeapAlloc(g_PIB->hPH, 0, MAX_PATH);
			CopyMemory(pFilePath, g_PIB->szCD, MAX_PATH);
			PathCchAppend(pFilePath, MAX_PATH, argv[2]);
			HANDLE hInputFile = CreateFileW(pFilePath, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			if (hInputFile) {
				DWORD dwWritten;
				status = WriteFile(hInputFile, pWrap, AES_BLOB_SIZE, &dwWritten, 0);
				CloseHandle(hInputFile);
			}

			FreeMemory(pWrap);
		} else if (!lstrcmpW(argv[1], L"/ek")) {
			// Get Full Path of Wrap Key / Import it ///////////////////////////////////////////
			PWSTR szFilePath = AllocMemory(MAX_PATH * sizeof(WCHAR), 0);
			CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH * sizeof(WCHAR));
			PathCchAppend(szFilePath, MAX_PATH, L"..\\RIFTKEY");
			HANDLE hFile = CreateFileW(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			LARGE_INTEGER liFS;
			BOOL status = GetFileSizeEx(hFile, &liFS);
			PVOID pFile = AllocMemory(liFS.LowPart, 0);
			DWORD dwRead;
			status = ReadFile(hFile, pFile, liFS.LowPart, &dwRead, 0);
			CloseHandle(hFile);

			// Open BCrypt Algorithm
			BCRYPT_ALG_HANDLE ah;
			BCryptOpenAlgorithmProvider(&ah, BCRYPT_AES_ALGORITHM, 0, 0);

			// Import WKey
			SIZE_T nResult;
			DWORD dwBL;
			BCRYPT_KEY_HANDLE khWrap;
			status = BCryptGetProperty(ah, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwBL, sizeof(DWORD), &nResult, 0);
			PBYTE pWrapObj = AllocMemory(dwBL, 0);
			status = BCryptImportKey(ah, 0, BCRYPT_KEY_DATA_BLOB, &khWrap, pWrapObj, dwBL, pFile, liFS.LowPart, 0);
			FreeMemory(pFile);

			// Get Full Path of string Key / Import it ///////////////////////////////////////////
			CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH * sizeof(WCHAR));
			PathCchAppend(szFilePath, MAX_PATH, L"..\\STRKEY");
			hFile = CreateFileW(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			status = GetFileSizeEx(hFile, &liFS);
			pFile = AllocMemory(liFS.LowPart, 0);
			status = ReadFile(hFile, pFile, liFS.LowPart, &dwRead, 0);
			CloseHandle(hFile);

			BCRYPT_KEY_HANDLE khKey;
			PBYTE pKeyObj = AllocMemory(dwBL, 0);
			status = BCryptImportKey(ah, 0, BCRYPT_KEY_DATA_BLOB, &khKey, pKeyObj, dwBL, pFile, liFS.LowPart, 0);
			FreeMemory(pFile);

			// ewww hardcoded size again
			PBYTE pWrappedKey = AllocMemory(24, 0);
			BCryptExportKey(khKey, khWrap, BCRYPT_AES_WRAP_KEY_BLOB, pWrappedKey, 24, &nResult, 0);

			BCryptDestroyKey(khKey);
			FreeMemory(pKeyObj);
			BCryptDestroyKey(khWrap);
			FreeMemory(pWrapObj);
			BCryptCloseAlgorithmProvider(ah, 0);

			PVOID pBaseKey = EBase64Encode(pWrappedKey, nResult, &nResult);
			FreeMemory(pWrappedKey);

			WriteConsoleA(g_hCon, pBaseKey, nResult, &nResult, 0);
			FreeMemory(pBaseKey);
		} else
			fnPrintF(L"Unknown Command", CON_ERROR);
	} if (argc == 4) {
		// Get Full Path of Wrap Key / Import it ///////////////////////////////////////////
		PWSTR szFilePath = AllocMemory(MAX_PATH * sizeof(WCHAR), 0);
		CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH * sizeof(WCHAR));
		PathCchAppend(szFilePath, MAX_PATH, L"..\\RIFTKEY");
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
		} else if (!lstrcmpW(argv[1], L"/de")) { ////////////////////////////////////////////////////////////////////////
			// Get Full Path of InputFile Parameter / Import it ////////////////////////////////////
			CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH);
			PathCchAppend(szFilePath, MAX_PATH, argv[2]);
			HANDLE hInputFile = CreateFileW(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (hInputFile == INVALID_HANDLE_VALUE) {
				fnPrintF(L"Can't open InputFile: \"%s\"\nErrorcode: 0x%08x\n", CON_ERROR, szFilePath, GetLastError());
				goto exit;
			}
			status = GetFileSizeEx(hInputFile, &liFS);
			if ((liFS.HighPart || !liFS.LowPart) || !status) {
				fnPrintF(L"Invalid FileSize\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			}

			PAESEX pAES = (PAESEX)AllocMemory(sizeof(AESEX), 0);
			PVOID pInputFile = AllocMemory(liFS.LowPart - sizeof(AESEX), 0);
			SIZE_T nInputFile;
			status = ReadFile(hInputFile, pAES, sizeof(AESEX), &nInputFile, 0);
			if (!status) {
				fnPrintF(L"Couldn't load InputFile\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			}
			status = ReadFile(hInputFile, pInputFile, liFS.LowPart - sizeof(AESEX), &nInputFile, 0);
			if (!status) {
				fnPrintF(L"Couldn't load InputFile\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			}
			CloseHandle(hInputFile);

			// Decryption // Open Provider //////////////////////////////////////////////////////////////////
			BCRYPT_ALG_HANDLE cahAES;
			status = BCryptOpenAlgorithmProvider(&cahAES, BCRYPT_AES_ALGORITHM, 0, 0);

			// Create KeyOBJ / Import KeySet
			DWORD dwBL;
			SIZE_T nResult;
			BCRYPT_KEY_HANDLE ckhAES, ckhWrap;
			status = BCryptGetProperty(cahAES, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwBL, sizeof(DWORD), &nResult, 0);
			PBYTE pAesObj = (PBYTE)AllocMemory(dwBL, 0);
			PBYTE pWrapObj = (PBYTE)AllocMemory(dwBL, 0);
			status = BCryptImportKey(cahAES, 0, BCRYPT_KEY_DATA_BLOB, &ckhWrap, pWrapObj, dwBL, (PUCHAR)pWrapBlob, AES_BLOB_SIZE, 0);
			status = BCryptImportKey(cahAES, ckhWrap, BCRYPT_AES_WRAP_KEY_BLOB, &ckhAES, pAesObj, dwBL, pAES->KEY, sizeof(pAES->KEY), 0);
			status = BCryptDestroyKey(ckhWrap);
			FreeMemory(pWrapObj);

			// Decrypt Data
			SIZE_T nDecrypted;
			status = BCryptDecrypt(ckhAES, (PBYTE)pInputFile, nInputFile, 0, pAES->IV, sizeof(pAES->IV), 0, 0, &nDecrypted, 0);
			PBYTE pDecrypted = (PBYTE)AllocMemory(nDecrypted, 0);
			status = BCryptDecrypt(ckhAES, (PBYTE)pInputFile, nInputFile, 0, pAES->IV, sizeof(pAES->IV), pDecrypted, nDecrypted, &nDecrypted, 0);

			// Free Data
			FreeMemory(pInputFile);
			status = BCryptDestroyKey(ckhAES);
			FreeMemory(pAesObj);
			status = BCryptCloseAlgorithmProvider(cahAES, 0);

			// Decompressor /////////////////////////////////////////////////////////
			DECOMPRESSOR_HANDLE dch;
			status = CreateDecompressor(COMPRESS_ALGORITHM_LZMS, 0, &dch);

			// Decompress Data
			SIZE_T nDecompressed;
			status = Decompress(dch, pDecrypted, nDecrypted, 0, 0, &nDecompressed);
			PBYTE pDecompressed = (PBYTE)AllocMemory(nDecompressed, 0);
			status = Decompress(dch, pDecrypted, nDecrypted, pDecompressed, nDecompressed, &nDecompressed);

			// Free Data
			FreeMemory(pDecrypted);
			CloseDecompressor(dch);

			// Checksum and Compare
			EMd5HashBegin();
			PVOID pMd5 = AllocMemory(16, 0);
			EMd5HashData(pMd5, pDecompressed, nDecompressed);
			if (EMd5Compare(pMd5, pAES->MD5))
				fnPrintF(L"CRC doesn't match !\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
			EMd5HashEnd();

			// Export File
			CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH);
			PathCchAppend(szFilePath, MAX_PATH, argv[3]);
			hInputFile = CreateFileW(szFilePath, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			if (hInputFile) {
				DWORD dwWritten;
				WriteFile(hInputFile, pDecompressed, nDecompressed, &dwWritten, 0);
				CloseHandle(hInputFile);
			}

			FreeMemory(pDecompressed);
		} else
			fnPrintF(L"Unknown Command\n", CON_ERROR);

		FreeMemory(szFilePath);
	}

exit:
	SetConsoleTextAttribute(g_hCon, csbi.wAttributes);
	FreeMemory(g_pBuf);

	return 0;
}