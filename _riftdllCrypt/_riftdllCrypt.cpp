#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "pathcch.lib")
#pragma comment(lib, "cabinet.lib")
#include <Windows.h>
#include <bcrypt.h>
#include <strsafe.h>
#include <PathCch.h>
#include <compressapi.h>

#define CON_SUCCESS (FOREGROUND_GREEN)                                           // 0b0010
#define CON_NORMAL  ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_BLUE)      // 0b0111
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   (FOREGROUND_RED | FOREGROUND_INTENSITY)                      // 0b1100

#include "..\_rift\crc32.c"

typedef struct {
	UCHAR KEY[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 32];
	UCHAR IV[16];
	UINT32 CRC;
} INFO;

// shitty debug/info print function
BOOL fnPrintF(PCWSTR pText, WORD wAttribute,  ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);
	HANDLE f_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
	const PVOID f_hBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (1 << 12));

	DWORD nBufLen;
	StringCchVPrintfW((STRSAFE_LPWSTR)f_hBuf, (1 << 12) / sizeof(WCHAR), pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)f_hBuf, (1 << 12) / sizeof(WCHAR), (PUINT32)&nBufLen);
	SetConsoleTextAttribute(f_hCon, wAttribute);
	WriteConsoleW(f_hCon, f_hBuf, nBufLen, &nBufLen, 0);

	va_end(vaArg);
	return nBufLen;
}

INT wmain(
	_In_     INT    argc,
	_In_     PWCHAR argv[],
	_In_opt_ PWCHAR envp[]
) {
	HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(hCon, &csbi);

	if (argc != 4) {
		fnPrintF(L"Usage: [en/de] [InputFile] [OutputName]\n\n"
		         L"\t[/en] : Encrypts the specified file with AES256 in CBC mode (random KEY, IV),\n"
		         L"\t        the encrypted file is then written to the the current directory.\n"
		         L"\t        The Application will also export the KEY, IV, a CRC Checksum of the original\n"
		         L"\t        and internal data (for the decryption part).\n\n"
		         L"\t[/de] : ", CON_WARNING);
		SetConsoleTextAttribute(hCon, csbi.wAttributes);
		goto exit;
	} else {
		// Get Current Directory ////////////////////////////////////////////////////////////////
		WCHAR szCD[MAX_PATH];
		GetCurrentDirectoryW(MAX_PATH, szCD);

		// Get Full Path of InputFile Parameter
		HANDLE hPH = GetProcessHeap();
		PWSTR pFileC = (PWSTR)HeapAlloc(hPH, 0, MAX_PATH);
		if (!pFileC) {
			fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
			goto exit;
		}
		CopyMemory(pFileC, szCD, MAX_PATH);
		PathCchAppend(pFileC, MAX_PATH, argv[2]);

		// Open InputFile
		HANDLE hFile = CreateFile(pFileC, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE) {
			fnPrintF(L"Can't open InputFile: \"%s\"\nErrorcode: 0x%08x", CON_ERROR, pFileC, GetLastError());
			goto exit;
		}

		// Get FileSize of InputFile
		LARGE_INTEGER liFS;
		BOOL status = GetFileSizeEx(hFile, &liFS);
		if ((liFS.HighPart || !liFS.LowPart) || !status) {
			fnPrintF(L"Invalid FileSize\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
			goto exit;
		}

		// Allocate FileBuffer and read File into Buf
		PVOID pFileBuf = HeapAlloc(hPH, 0, liFS.LowPart);
		if (!pFileBuf) {
			fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
			goto exit;
		}
		DWORD dwRead;
		BOOL bRF = ReadFile(hFile, pFileBuf, liFS.LowPart, &dwRead, 0);
		if (!bRF) {
			fnPrintF(L"Couldn't load InputFile\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
			goto exit;
		}
		CloseHandle(hFile);

		if (!lstrcmpW(argv[1], L"/en")) {
			// allocate info structure and generate crc from input //////////////////////////////////////
			INFO* dataI = (INFO*)malloc(sizeof(INFO));
			fnAllocTable();
			dataI->CRC = fnCRC32((PUCHAR)pFileBuf, dwRead);

			// allocate LZMS compressor ///////////////////////////////////////////////////////////////////
			COMPRESSOR_HANDLE hC;
			status = CreateCompressor(COMPRESS_ALGORITHM_LZMS, 0, &hC);
			if (!status) {
				fnPrintF(L"Couldn't create compressor\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
				goto exit;
			}

			// calculate compressed filesize and allocate buffer
			SIZE_T dwCompressed;
			PVOID pCompressed = 0;
			status = Compress(hC, pFileBuf, dwRead, 0, 0, &dwCompressed);
			if (!status) {
				DWORD err = GetLastError();
				if (err != ERROR_INSUFFICIENT_BUFFER) {
					fnPrintF(L"Couldn't compress Data\nErrorcode: 0x%08x", CON_ERROR);
					goto exit;
				}
				else {
					pCompressed = HeapAlloc(hPH, 0, dwCompressed);
					if (!pCompressed) {
						fnPrintF(L"Couldn't allocate buffer\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
						goto exit;
					}
				}
			}

			// compress File
			status = Compress(hC, pFileBuf, dwRead, pCompressed, dwCompressed, &dwCompressed);
			if (!status) {
				fnPrintF(L"Couldn't compress Data\nErrorcode: 0x%08x", CON_ERROR, GetLastError());
				goto exit;
			}
			if (dwCompressed > dwRead)
				fnPrintF(L"Compressed File will be bigger the original\nThis will be updated", CON_WARNING);

			// Open Algorithm Providers ///////////////////////////////////////////////////////////////////
			BCRYPT_ALG_HANDLE cah;
			BCRYPT_ALG_HANDLE RNG;
			status = BCryptOpenAlgorithmProvider(&cah, BCRYPT_AES_ALGORITHM, 0, 0);
			status = BCryptOpenAlgorithmProvider(&RNG, BCRYPT_RNG_ALGORITHM, 0, 0);

			// Generate Key From Data
			PUCHAR pKey = (PUCHAR)malloc(32);
			BCryptGenRandom(RNG, pKey, 32, 0);

			// Generate AES Key OBJ
			DWORD out, result;
			BCRYPT_KEY_HANDLE ckh;
			status = BCryptGenerateSymmetricKey(cah, &ckh, 0, 0, pKey, 32, 0);

			// Export Key
			BCRYPT_KEY_DATA_BLOB_HEADER ckdbh;
			BCryptExportKey(ckh, 0, BCRYPT_KEY_DATA_BLOB, dataI->KEY, result, &result, 0);

			// Calculate, allocate and init initialization-vector
			status = BCryptGetProperty(cah, BCRYPT_BLOCK_LENGTH, (PUCHAR)&out, sizeof(DWORD), &result, 0);
			BCryptGenRandom(RNG, dataI->IV, out, 0);
			PUCHAR IV = (PUCHAR)malloc(out);
			CopyMemory(IV, dataI->IV, out);

			// Encrypt Data
			status = BCryptEncrypt(ckh, (PUCHAR)pCompressed, dwCompressed, 0, IV, out, 0, 0, &result, BCRYPT_BLOCK_PADDING);
			PUCHAR eData = (PUCHAR)malloc(result);
			status = BCryptEncrypt(ckh, (PUCHAR)pCompressed, dwCompressed, 0, IV, out, eData, result, &result, BCRYPT_BLOCK_PADDING);

			BCryptDestroyKey(ckh);
			BCryptCloseAlgorithmProvider(cah, 0);
			BCryptCloseAlgorithmProvider(RNG, 0);

			// Export Data ///////////////////////////////////////////////////////////////////////////
			CopyMemory(pFileC, szCD, MAX_PATH);
			PathCchAppend(pFileC, MAX_PATH, argv[3]);
			PathCchAddExtension(pFileC, MAX_PATH, L".cRy");
			hFile = CreateFileW(pFileC, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_ENCRYPTED, 0);
			if (hFile) {
				DWORD dwWritten;
				WriteFile(hFile, eData, result, &dwWritten, 0);
				CloseHandle(hFile);
			}

			CopyMemory(pFileC, szCD, MAX_PATH);
			PathCchAppend(pFileC, MAX_PATH, argv[3]);
			PathCchAddExtension(pFileC, MAX_PATH, L".eKy");
			hFile = CreateFileW(pFileC, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_ENCRYPTED, 0);
			if (hFile) {
				DWORD dwWritten;
				WriteFile(hFile, dataI, sizeof(INFO), &dwWritten, 0);
				CloseHandle(hFile);
			}
		} else if (!lstrcmpW(argv[1], L"/de")) {

		}

		HeapFree(hPH, 0, pFileC);
	}

exit:
	SetConsoleTextAttribute(hCon, csbi.wAttributes);

	return 0;
}