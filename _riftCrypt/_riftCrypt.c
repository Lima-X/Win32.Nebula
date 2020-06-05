// This project is just a mess,
// most of the sizes are not calculated dynamically and are hard coded,
// also there're no actual sanity checks as i didn't care for them.
// this is just a support tool after all
// and only serves the purpose to prepare files for the loader.
// tbh i just wanted to be done with this as it is already 300+ lines
// for just a support tool (why do i do this to myself)
// I should also add that this tool does NOT clean up properly,
// as it isn't required, the actual decryption module in the loader does.

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

// shitty debug/info print function
BOOL fnPrintF(PCWSTR pText, WORD wAttribute, ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);

	DWORD nBufLen;
	StringCchVPrintfW((STRSAFE_LPWSTR)g_pBuf, (1 << 12) / sizeof(WCHAR), pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)g_pBuf, (1 << 12) / sizeof(WCHAR), (PUINT32)&nBufLen);
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
	g_hPH = GetProcessHeap();
	g_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
	g_pBuf = HeapAlloc(g_hPH, HEAP_ZERO_MEMORY, (1 << 12));

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(g_hCon, &csbi);
	WCHAR szCD[MAX_PATH];
	GetCurrentDirectoryW(MAX_PATH, szCD);

	if ((argc != 4) && (argc != 3)) {
		fnPrintF(L"Usage: [gw] [KeyFileName]/([en/de] [InputFile] [OutputName/File])\n\n"
		         L"\t[/en] : Encrypts the specified file with AES256 in CBC mode (random KEY, pIV),\n"
		         L"\t        the encrypted file is then written to the the current directory.\n"
		         L"\t        The Application will also export the KEY, pIV, a CRC Checksum of the original\n"
		         L"\t        and internal data (for the decryption part).\n\n"
		         L"\t[/de] : Decrypts and decompresses the specified file,\n"
		         L"\t        it also validates that the decrypted content is not corrupted.\n\n"
		         L"\t[/gw] : Generates the wrap Key used to encrypt the key,\n"
		         L"\t        that is packed into the encryped data package.\n", CON_WARNING);
	} else if (argc == 3) {
		if (!lstrcmpW(argv[1], L"/gw")) {
			BCRYPT_ALG_HANDLE cahAES, cahRNG;
			NTSTATUS status = BCryptOpenAlgorithmProvider(&cahAES, BCRYPT_AES_ALGORITHM, 0, 0);
			status = BCryptOpenAlgorithmProvider(&cahRNG, BCRYPT_RNG_ALGORITHM, 0, 0);

			PBYTE pWrap = (PBYTE)HeapAlloc(g_hPH, 0, AES_KEY_SIZE);
			status = BCryptGenRandom(cahRNG, pWrap, AES_KEY_SIZE, 0);
			status = BCryptCloseAlgorithmProvider(cahRNG, 0);

			BCRYPT_KEY_HANDLE ckhWrap;
			status = BCryptGenerateSymmetricKey(cahAES, &ckhWrap, 0, 0, pWrap, AES_KEY_SIZE, 0);
			HeapFree(g_hPH, 0, pWrap);

			SIZE_T nResult;
			pWrap = (PBYTE)HeapAlloc(g_hPH, 0, WRAP_BLOB_SIZE);
			status = BCryptExportKey(ckhWrap, 0, BCRYPT_KEY_DATA_BLOB, pWrap, WRAP_BLOB_SIZE, &nResult, 0);
			status = BCryptDestroyKey(ckhWrap);
			BCryptCloseAlgorithmProvider(cahAES, 0);

			PWSTR pFilePath = (PWSTR)HeapAlloc(g_hPH, 0, MAX_PATH);
			CopyMemory(pFilePath, szCD, MAX_PATH);
			PathCchAppend(pFilePath, MAX_PATH, argv[2]);
			HANDLE hInputFile = CreateFileW(pFilePath, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			if (hInputFile) {
				DWORD dwWritten;
				status = WriteFile(hInputFile, pWrap, WRAP_BLOB_SIZE, &dwWritten, 0);
				CloseHandle(hInputFile);
			}

			HeapFree(g_hPH, 0, pWrap);
		} else
			fnPrintF(L"Unknown Command", CON_ERROR);
	} else if (argc == 4) {
		// Get Full Path of Wrap Key / Import it ///////////////////////////////////////////
		PWSTR szFilePath = (PWSTR)HeapAlloc(g_hPH, 0, MAX_PATH);
		CopyMemory(szFilePath, szCD, MAX_PATH);
		PathCchAppend(szFilePath, MAX_PATH, L"RIFTKEY");
		HANDLE hWrapBlob = CreateFileW(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hWrapBlob == INVALID_HANDLE_VALUE) {
			fnPrintF(L"Can't open InputFile: \"%s\"\nErrorcode: 0x%08x\n", CON_ERROR, szFilePath, GetLastError());
			goto exit;
		}
		LARGE_INTEGER liFS;
		BOOL status = GetFileSizeEx(hWrapBlob, &liFS);
		if (!status || ((liFS.HighPart || !liFS.LowPart) && (liFS.LowPart != WRAP_BLOB_SIZE))) {
			fnPrintF(L"Invalid FileSize\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
			goto exit;
		}
		PVOID pWrapBlob = HeapAlloc(g_hPH, 0, liFS.LowPart);
		if (!pWrapBlob) {
			fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
			goto exit;
		}
		DWORD dwRead;
		status = ReadFile(hWrapBlob, pWrapBlob, liFS.LowPart, &dwRead, 0);
		if (!status) {
			fnPrintF(L"Couldn't load InputFile\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
			goto exit;
		}
		CloseHandle(hWrapBlob);

		if (!lstrcmpW(argv[1], L"/en")) {
			// Get Full Path of InputFile Parameter / Import it ////////////////////////////////////
			CopyMemory(szFilePath, szCD, MAX_PATH);
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
			PVOID pInputFile = HeapAlloc(g_hPH, 0, liFS.LowPart);
			if (!pInputFile) {
				fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			}
			SIZE_T nInputFile;
			status = ReadFile(hInputFile, pInputFile, liFS.LowPart, &nInputFile, 0);
			if (!status) {
				fnPrintF(L"Couldn't load InputFile\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			}
			CloseHandle(hInputFile);

			// allocate info structure and generate crc from input //////////////////////////////////////
			fnAllocTable();
			PAESEX pAES = (PAESEX)HeapAlloc(g_hPH, 0, sizeof(AESEX));
			pAES->CRC = fnCRC32((PBYTE)pInputFile, nInputFile);

			// allocate LZMS compressor ///////////////////////////////////////////////////////////////////
			COMPRESSOR_HANDLE ch;
			status = CreateCompressor(COMPRESS_ALGORITHM_LZMS, 0, &ch);
			if (!status) {
				fnPrintF(L"Couldn't create compressor\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			}

			// calculate compressed filesize and allocate buffer
			SIZE_T nCompressed;
			PBYTE pCompressed = 0;
			status = Compress(ch, pInputFile, nInputFile, 0, 0, &nCompressed);
			if (!status) {
				DWORD dwError = GetLastError();
				if (dwError != ERROR_INSUFFICIENT_BUFFER) {
					fnPrintF(L"Couldn't compress Data\nErrorcode: 0x%08x\n", CON_ERROR);
					goto exit;
				} else {
					pCompressed = (PBYTE)HeapAlloc(g_hPH, 0, nCompressed);
					if (!pCompressed) {
						fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
						goto exit;
					}
				}
			}

			// compress File
			status = Compress(ch, pInputFile, nInputFile, pCompressed, nCompressed, &nCompressed);
			if (!status) {
				fnPrintF(L"Couldn't compress Data\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			} if (nCompressed > nInputFile) // <- Unlikely
				fnPrintF(L"Compressed File will be bigger the original\nThis will be updated\n", CON_WARNING);

			// Free Data
			HeapFree(g_hPH, 0, pInputFile);
			CloseCompressor(ch);

			// Open Algorithm Providers ///////////////////////////////////////////////////////////////////
			BCRYPT_ALG_HANDLE cahAES, cahRNG;
			status = BCryptOpenAlgorithmProvider(&cahAES, BCRYPT_AES_ALGORITHM, 0, 0);
			status = BCryptOpenAlgorithmProvider(&cahRNG, BCRYPT_RNG_ALGORITHM, 0, 0);

			// Generate Key From Data
			PBYTE pKey = (PBYTE)HeapAlloc(g_hPH, 0, AES_KEY_SIZE);
			status = BCryptGenRandom(cahRNG, pKey, AES_KEY_SIZE, 0);

			// Allocate key objects, generate AES key's and export them
			SIZE_T nResult;
			DWORD dwBL;
			BCRYPT_KEY_HANDLE ckhAES, ckhWrap;
			status = BCryptGetProperty(cahAES, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwBL, sizeof(DWORD), &nResult, 0);
			PBYTE pAesObj = (PBYTE)HeapAlloc(g_hPH, 0, dwBL);
			status = BCryptImportKey(cahAES, 0, BCRYPT_KEY_DATA_BLOB, &ckhWrap, pAesObj, dwBL, (PUCHAR)pWrapBlob, WRAP_BLOB_SIZE, 0);
			status = BCryptGenerateSymmetricKey(cahAES, &ckhAES, 0, 0, pKey, AES_KEY_SIZE, 0);
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
			CopyMemory(szFilePath, szCD, MAX_PATH);
			PathCchAppend(szFilePath, MAX_PATH, argv[3]);
			hInputFile = CreateFileW(szFilePath, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED), 0);
			if (hInputFile) {
				status = WriteFile(hInputFile, pAES, sizeof(AESEX), &dwWritten, 0);
				status = WriteFile(hInputFile, pEncrypted, nResult, &dwWritten, 0);
				CloseHandle(hInputFile);
			}
			HeapFree(g_hPH, 0, pEncrypted);
			HeapFree(g_hPH, 0, pAES);
		} else if (!lstrcmpW(argv[1], L"/de")) { ////////////////////////////////////////////////////////////////////////
			// Get Full Path of InputFile Parameter / Import it ////////////////////////////////////
			CopyMemory(szFilePath, szCD, MAX_PATH);
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

			PAESEX pAES = (PAESEX)HeapAlloc(g_hPH, 0, sizeof(AESEX));
			PVOID pInputFile = HeapAlloc(g_hPH, 0, liFS.LowPart - sizeof(AESEX));
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
			PBYTE pAesObj = (PBYTE)HeapAlloc(g_hPH, 0, dwBL);
			PBYTE pWrapObj = (PBYTE)HeapAlloc(g_hPH, 0, dwBL);
			status = BCryptImportKey(cahAES, 0, BCRYPT_KEY_DATA_BLOB, &ckhWrap, pWrapObj, dwBL, (PUCHAR)pWrapBlob, WRAP_BLOB_SIZE, 0);
			status = BCryptImportKey(cahAES, ckhWrap, BCRYPT_AES_WRAP_KEY_BLOB, &ckhAES, pAesObj, dwBL, pAES->KEY, sizeof(pAES->KEY), 0);
			status = BCryptDestroyKey(ckhWrap);
			HeapFree(g_hPH, 0, pWrapObj);

			// Decrypt Data
			SIZE_T nDecrypted;
			status = BCryptDecrypt(ckhAES, (PBYTE)pInputFile, nInputFile, 0, pAES->IV, sizeof(pAES->IV), 0, 0, &nDecrypted, 0);
			PBYTE pDecrypted = (PBYTE)HeapAlloc(g_hPH, 0, nDecrypted);
			status = BCryptDecrypt(ckhAES, (PBYTE)pInputFile, nInputFile, 0, pAES->IV, sizeof(pAES->IV), pDecrypted, nDecrypted, &nDecrypted, 0);

			// Free Data
			HeapFree(g_hPH, 0, pInputFile);
			status = BCryptDestroyKey(ckhAES);
			HeapFree(g_hPH, 0, pAesObj);
			status = BCryptCloseAlgorithmProvider(cahAES, 0);

			// Decompressor /////////////////////////////////////////////////////////
			DECOMPRESSOR_HANDLE dch;
			status = CreateDecompressor(COMPRESS_ALGORITHM_LZMS, 0, &dch);

			// Decompress Data
			SIZE_T nDecompressed;
			status = Decompress(dch, pDecrypted, nDecrypted, 0, 0, &nDecompressed);
			PBYTE pDecompressed = (PBYTE)HeapAlloc(g_hPH, 0, nDecompressed);
			status = Decompress(dch, pDecrypted, nDecrypted, pDecompressed, nDecompressed, &nDecompressed);

			// Free Data
			HeapFree(g_hPH, 0, pDecrypted);
			CloseDecompressor(dch);

			// Checksum and Compare
			fnAllocTable();
			DWORD dwCrc = fnCRC32(pDecompressed, nDecompressed);
			if (dwCrc != pAES->CRC) {
				fnPrintF(L"CRC doesn't match !\nErrorcode: 0x%08x\n", CON_ERROR, GetLastError());
				goto exit;
			}

			// Export File
			CopyMemory(szFilePath, szCD, MAX_PATH);
			PathCchAppend(szFilePath, MAX_PATH, argv[3]);
			hInputFile = CreateFileW(szFilePath, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			if (hInputFile) {
				DWORD dwWritten;
				WriteFile(hInputFile, pDecompressed, nDecompressed, &dwWritten, 0);
				CloseHandle(hInputFile);
			}

			HeapFree(g_hPH, 0, pDecompressed);
		} else
			fnPrintF(L"Unknown Command\n", CON_ERROR);

		HeapFree(g_hPH, 0, szFilePath);
	}

exit:
	SetConsoleTextAttribute(g_hCon, csbi.wAttributes);
	HeapFree(g_hPH, 0, g_pBuf);

	return 0;
}