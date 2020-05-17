#include <Windows.h>
#pragma comment(lib, "bcrypt.lib")
#include <bcrypt.h>
#pragma comment(lib, "cabinet.lib")
#include <compressapi.h>
#pragma comment(lib, "pathcch.lib")
#include <PathCch.h>
#include <strsafe.h>
EXTERN_C {
	#include "..\_rift\_rift_shared.h"
}

#define CON_SUCCESS (FOREGROUND_GREEN)                                           // 0b0010
#define CON_INFO  ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_BLUE)      // 0b0111
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   (FOREGROUND_RED  | FOREGROUND_INTENSITY)                     // 0b1100

HANDLE g_hCon;
PVOID g_hBuf;

// shitty debug/info print function
BOOL fnPrintF(PCWSTR pText, WORD wAttribute,  ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);

	DWORD nBufLen;
	StringCchVPrintfW((STRSAFE_LPWSTR)g_hBuf, (1 << 12) / sizeof(WCHAR), pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)g_hBuf, (1 << 12) / sizeof(WCHAR), (PUINT32)&nBufLen);
	SetConsoleTextAttribute(g_hCon, wAttribute);
	WriteConsoleW(g_hCon, g_hBuf, nBufLen, &nBufLen, 0);

	va_end(vaArg);
	return nBufLen;
}

INT wmain(
	_In_     INT    argc,
	_In_     PWCHAR argv[],
	_In_opt_ PWCHAR envp[]
) {
	UNREFERENCED_PARAMETER(envp);
	g_hPH = GetProcessHeap();
	g_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
	g_hBuf = HeapAlloc(g_hPH, HEAP_ZERO_MEMORY, (1 << 12));
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(g_hCon, &csbi);

	if (argc != 4) {
		fnPrintF(L"Usage: [en/de] [InputFile] [OutputName]\n\n"
		         L"\t[/en] : Encrypts the specified file with AES256 in CBC mode (random KEY, pIV),\n"
		         L"\t        the encrypted file is then written to the the current directory.\n"
		         L"\t        The Application will also export the KEY, pIV, a CRC Checksum of the original\n"
		         L"\t        and internal data (for the decryption part).\n\n"
		         L"\t[/de] : Decrypts and decompresses the specified file,"
		         L"\t        it also validates that the decrypted content is not corrupted.", CON_WARNING);
		goto exit;
	} else {
		// Get Current Directory
		WCHAR szCD[MAX_PATH];
		GetCurrentDirectoryW(MAX_PATH, szCD);

		// Get Full Path of InputFile Parameter
		PWSTR pFilePath = (PWSTR)HeapAlloc(g_hPH, 0, MAX_PATH);
		if (!pFilePath) {
			fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
			goto exit;
		}
		CopyMemory(pFilePath, szCD, MAX_PATH);
		PathCchAppend(pFilePath, MAX_PATH, argv[2]);

		// Open InputFile
		HANDLE hInputFile = CreateFile(pFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hInputFile == INVALID_HANDLE_VALUE) {
			fnPrintF(L"Can't open InputFile: \"%s\"\nErrorcode: 0x%08x", CON_ERROR, pFilePath, GetLastError());
			goto exit;
		}

		// Get FileSize of InputFile
		LARGE_INTEGER liIFS;
		BOOL status = GetFileSizeEx(hInputFile, &liIFS);
		if ((liIFS.HighPart || !liIFS.LowPart) || !status) {
			fnPrintF(L"Invalid FileSize\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
			goto exit;
		}

		// Allocate FileBuffer and read File into Buf
		PVOID pInputFileBuf = HeapAlloc(g_hPH, 0, liIFS.LowPart);
		if (!pInputFileBuf) {
			fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
			goto exit;
		}
		SIZE_T nInputFileBuf;
		BOOL bRF = ReadFile(hInputFile, pInputFileBuf, liIFS.LowPart, &nInputFileBuf, 0);
		if (!bRF) {
			fnPrintF(L"Couldn't load InputFile\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
			goto exit;
		}
		CloseHandle(hInputFile);

		if (!lstrcmpW(argv[1], L"/en")) {
			// allocate info structure and generate crc from input //////////////////////////////////////
			fnAllocTable();
			PAESKEY pAES = (PAESKEY)HeapAlloc(g_hPH, 0, sizeof(AESKEY));
			pAES->CRC = fnCRC32((PBYTE)pInputFileBuf, nInputFileBuf);

			// allocate LZMS compressor ///////////////////////////////////////////////////////////////////
			COMPRESSOR_HANDLE ch;
			status = CreateCompressor(COMPRESS_ALGORITHM_LZMS, 0, &ch);
			if (!status) {
				fnPrintF(L"Couldn't create compressor\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
				goto exit;
			}

			// calculate compressed filesize and allocate buffer
			SIZE_T nCompressed;
			PBYTE pCompressed = 0;
			status = Compress(ch, pInputFileBuf, nInputFileBuf, 0, 0, &nCompressed);
			if (!status) {
				DWORD dwError = GetLastError();
				if (dwError != ERROR_INSUFFICIENT_BUFFER) {
					fnPrintF(L"Couldn't compress Data\nErrorcode: 0x%08x", CON_ERROR);
					goto exit;
				} else {
					pCompressed = (PBYTE)HeapAlloc(g_hPH, 0, nCompressed);
					if (!pCompressed) {
						fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
						goto exit;
					}
				}
			}

			// compress File
			status = Compress(ch, pInputFileBuf, nInputFileBuf, pCompressed, nCompressed, &nCompressed);
			if (!status) {
				fnPrintF(L"Couldn't compress Data\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
				goto exit;
			} if (nCompressed > nInputFileBuf)
				fnPrintF(L"Compressed File will be bigger the original\nThis will be updated", CON_WARNING);
			HeapFree(g_hPH, 0, pInputFileBuf);

			// Open Algorithm Providers ///////////////////////////////////////////////////////////////////
			BCRYPT_ALG_HANDLE cahAES;
			BCRYPT_ALG_HANDLE cahRNG;
			status = BCryptOpenAlgorithmProvider(&cahAES, BCRYPT_AES_ALGORITHM, 0, 0);
			status = BCryptOpenAlgorithmProvider(&cahRNG, BCRYPT_RNG_ALGORITHM, 0, 0);

			// Generate Key From Data
			PBYTE pKey = (PBYTE)HeapAlloc(g_hPH, 0, 32);
			status = BCryptGenRandom(cahRNG, pKey, 32, 0);
			PBYTE pWrap = (PBYTE)HeapAlloc(g_hPH, 0, 32);
			status = BCryptGenRandom(cahRNG, pWrap, 32, 0);

			// Allocate key objects, generate AES key's and export them
			SIZE_T nResult;
			BCRYPT_KEY_HANDLE ckhAES, ckhWrap = 0;
			status = BCryptGenerateSymmetricKey(cahAES, &ckhWrap, 0, 0, pKey, 32, 0);
			status = BCryptExportKey(ckhWrap, 0, BCRYPT_KEY_DATA_BLOB, pAES->WRAP, sizeof(pAES->WRAP), &nResult, 0);
			status = BCryptGenerateSymmetricKey(cahAES, &ckhAES, 0, 0, pKey, 32, 0);
			status = BCryptExportKey(ckhAES, ckhWrap, BCRYPT_AES_WRAP_KEY_BLOB, pAES->KEY, sizeof(pAES->KEY), &nResult, 0);
			status = BCryptDestroyKey(ckhWrap);

			// init initialization-vector and copy
			status = BCryptGenRandom(cahRNG, pAES->IV, 16, 0);
			PBYTE pIV = (PBYTE)HeapAlloc(g_hPH, 0, 16);
			CopyMemory(pIV, pAES->IV, 16);

			// Encrypt Data
			status = BCryptEncrypt(ckhAES, (PBYTE)pCompressed, nCompressed, 0, pIV, 16, 0, 0, &nResult, BCRYPT_BLOCK_PADDING);
			PBYTE pEncrypted = (PBYTE)HeapAlloc(g_hPH, 0, nResult);
			status = BCryptEncrypt(ckhAES, (PBYTE)pCompressed, nCompressed, 0, pIV, 16, pEncrypted, nResult, &nResult, BCRYPT_BLOCK_PADDING);

			HeapFree(g_hPH, 0, pCompressed);
			status = BCryptDestroyKey(ckhAES);
			status = BCryptCloseAlgorithmProvider(cahAES, 0);
			status = BCryptCloseAlgorithmProvider(cahRNG, 0);

			// Export Data ///////////////////////////////////////////////////////////////////////////
			DWORD dwWritten;
			CopyMemory(pFilePath, szCD, MAX_PATH);
			PathCchAppend(pFilePath, MAX_PATH, argv[3]);
			PathCchAddExtension(pFilePath, MAX_PATH, L".cRy");
			hInputFile = CreateFileW(pFilePath, GENERIC_ALL, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED, 0);
			if (hInputFile) {
				status = WriteFile(hInputFile, pEncrypted, nResult, &dwWritten, 0);
				CloseHandle(hInputFile);
				HeapFree(g_hPH, 0, pEncrypted);
			}

			CopyMemory(pFilePath, szCD, MAX_PATH);
			PathCchAppend(pFilePath, MAX_PATH, argv[3]);
			PathCchAddExtension(pFilePath, MAX_PATH, L".eKy");
			hInputFile = CreateFileW(pFilePath, GENERIC_ALL, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_ENCRYPTED, 0);
			if (hInputFile) {
				status = WriteFile(hInputFile, pAES, sizeof(AESKEY), &dwWritten, 0);
				CloseHandle(hInputFile);
				HeapFree(g_hPH, 0, pAES);
			}
		} else if (!lstrcmpW(argv[1], L"/de")) { ////////////////////////////////////////////////////////////////////////
			PWSTR pKeyD = (PWSTR)HeapAlloc(g_hPH, 0, MAX_PATH);
			if (!pKeyD) {
				fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
				goto exit;
			}
			CopyMemory(pKeyD, pFilePath, MAX_PATH);
			PathCchRemoveExtension(pKeyD, MAX_PATH);
			PathCchAddExtension(pKeyD, MAX_PATH, L".eKy");

			// Open KeyData
			HANDLE hBlob = CreateFile(pKeyD, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_ENCRYPTED, 0);
			if (hBlob == INVALID_HANDLE_VALUE) {
				fnPrintF(L"Can't open InputFile: \"%s\"\nErrorcode: 0x%08x", CON_ERROR, pKeyD, GetLastError());
				goto exit;
			}

			// Get FileSize of InputFile
			status = GetFileSizeEx(hBlob, &liIFS);
			if (((liIFS.HighPart || !liIFS.LowPart) || !status) && (liIFS.LowPart != sizeof(AESKEY))) {
				fnPrintF(L"Invalid FileSize\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
				goto exit;
			}

			// Allocate FileBuffer and read File into Buf
			PAESKEY pBlobBuf = (PAESKEY)HeapAlloc(g_hPH, 0, sizeof(AESKEY));
			if (!pBlobBuf) {
				fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
				goto exit;
			}
			DWORD dwReadKey;
			bRF = ReadFile(hBlob, pBlobBuf, sizeof(AESKEY), &dwReadKey, 0);
			if (!bRF) {
				fnPrintF(L"Couldn't load InputFile\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
				goto exit;
			}
			CloseHandle(hBlob);

			// Decryption // Open Provider //////////////////////////////////////////////////////////////////
			BCRYPT_ALG_HANDLE cahAES;
			status = BCryptOpenAlgorithmProvider(&cahAES, BCRYPT_AES_ALGORITHM, 0, 0);

			// Create KeyOBJ
			DWORD dwBL;
			SIZE_T nResult;
			BCRYPT_KEY_HANDLE ckhAES, ckhWrap = 0;
			status = BCryptGetProperty(cahAES, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwBL, sizeof(DWORD), &nResult, 0);
			PBYTE pAesObj = (PBYTE)HeapAlloc(g_hPH, 0, dwBL);
			PBYTE pWrapObj = (PBYTE)HeapAlloc(g_hPH, 0, dwBL);

			DWORD result, out;
			status = BCryptGetProperty(cahAES, BCRYPT_OBJECT_LENGTH, (PBYTE)&out, sizeof(DWORD), &result, 0);
			PBYTE pKeyOBJ = (PBYTE)HeapAlloc(g_hPH, 0, out);
			PBYTE pKeyWRAPOBJ = (PBYTE)HeapAlloc(g_hPH, 0, out);

			// Import Key
			BCRYPT_KEY_HANDLE ckh, ckhWRAP;
			status = BCryptImportKey(cahAES, 0, BCRYPT_KEY_DATA_BLOB, &ckhWRAP, pKeyWRAPOBJ, out, pBlobBuf->WRAP, sizeof(pBlobBuf->WRAP), 0);
			status = BCryptImportKey(cahAES, ckhWRAP, BCRYPT_KEY_DATA_BLOB, &ckh, pKeyOBJ, out, pBlobBuf->KEY, sizeof(pBlobBuf->KEY), 0);
			BCryptDestroyKey(ckhWRAP);
			HeapFree(g_hPH, 0, pKeyWRAPOBJ);

			// Decrypt Data
			status = BCryptDecrypt(ckh, (PBYTE)pInputFileBuf, nInputFileBuf, 0, pBlobBuf->IV, sizeof(pBlobBuf->IV), 0, 0, &result, 0);
			PBYTE dData = (PBYTE)malloc(result);
			status = BCryptDecrypt(ckh, (PBYTE)pInputFileBuf, nInputFileBuf, 0, pBlobBuf->IV, sizeof(pBlobBuf->IV), dData, result, &result, 0);
			status = BCryptDestroyKey(ckh);
			status = BCryptCloseAlgorithmProvider(cahAES, 0);

			// Decompressor /////////////////////////////////////////////////////////
			DECOMPRESSOR_HANDLE dch;
			status = CreateDecompressor(COMPRESS_ALGORITHM_LZMS, 0, &dch);

			DWORD dwuncompressed;
			status = Decompress(dch, dData, result, 0, 0, &dwuncompressed);
			PBYTE pUnData = (PBYTE)malloc(dwuncompressed);
			status = Decompress(dch, dData, result, pUnData, dwuncompressed, &dwuncompressed);

			fnAllocTable();
			DWORD crct = fnCRC32(pUnData, dwuncompressed);
			if (crct != pBlobBuf->CRC) {
				fnPrintF(L"CRC doesn't match !\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
				goto exit;
			}

			// Export File
			CopyMemory(pFilePath, szCD, MAX_PATH);
			PathCchAppend(pFilePath, MAX_PATH, argv[3]);
			PathCchAddExtension(pFilePath, MAX_PATH, L".dll");
			hInputFile = CreateFileW(pFilePath, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			if (hInputFile) {
				DWORD dwWritten;
				WriteFile(hInputFile, pUnData, dwuncompressed, &dwWritten, 0);
				CloseHandle(hInputFile);
			}
		}

		HeapFree(g_hPH, 0, pFilePath);
	}

exit:
	SetConsoleTextAttribute(g_hCon, csbi.wAttributes);
	HeapFree(g_hPH, 0, g_hBuf);

	return 0;
}