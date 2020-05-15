#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "pathcch.lib")
#include <Windows.h>
#include <bcrypt.h>
#include <strsafe.h>
#include <PathCch.h>

#define CON_SUCCESS (FOREGROUND_GREEN)                                           // 0b0010
#define CON_NORMAL  ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_BLUE)      // 0b0111
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   (FOREGROUND_RED | FOREGROUND_INTENSITY)                      // 0b1100

typedef struct {
	PUCHAR KEY[32];
	PUCHAR IV[16];
	UINT32 CRC;
};

BOOL fnPrintF(PCWSTR pText, WORD wAttribute,  ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);
	const static HANDLE f_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
	const static PVOID f_hBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (1 << 12));

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
	if (argc != 3) {
		fnPrintF(L"Usage: [en/de] [InputFile]\n\n"
		         L"       [/en] : Encrypts the specified file with AES256 in CBC mode (random KEY, IV),\n"
		         L"               the encrypted file is then written to the the current directory.\n"
		         L"               The Application will also export the KEY, IV, a CRC Checksum of the original"
		         L"               and internal data (for the decryption part).\n\n"
		         L"       [/de] : ", CON_WARNING);
		return 1;
	} else {
		// Get Current Directory
		WCHAR szCD[MAX_PATH];
		GetCurrentDirectoryW(MAX_PATH, szCD);

		// Get Full Path of InputFile Parameter
		HANDLE hPH = GetProcessHeap();
		PWSTR pFileC = (PWSTR)HeapAlloc(hPH, 0, MAX_PATH);
		CopyMemory(pFileC, szCD, MAX_PATH);
		PathCchAppend(pFileC, MAX_PATH, argv[2]);

		// Open InputFile
		HANDLE hFile = CreateFile(pFileC, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE) {
			fnPrintF(L"Can't open InputFile: \"%s\"", CON_ERROR, pFileC);
			return 1;
		}

		// Get FileSize of InputFile
		LARGE_INTEGER liFS;
		GetFileSizeEx(hFile, &liFS);
		if (liFS.HighPart || !liFS.LowPart) {
			fnPrintF(L"Invalid FileSize", CON_ERROR, pFileC);
			return 2;
		}

		if (!lstrcmpW(argv[1], L"/en")) {

		} else if (!lstrcmpW(argv[1], L"/de")) {

		}

		HeapFree(hPH, 0, pFileC);
	}

	return 0;
}