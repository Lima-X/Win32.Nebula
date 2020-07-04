#include "_rift.h"

static DWORD WINAPI thConsoleTitle(_In_ PVOID pParam);
static DWORD WINAPI thBootScreen(_In_ PVOID pParam);
static HANDLE l_hCon;

BOOL IOpenConsole() {
	BOOL bT = AllocConsole();
	if (bT) {
		l_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
		HANDLE hTH[2];
		hTH[0] = CreateThread(NULL, 0, thConsoleTitle, NULL, NULL, 0);
		hTH[1] = CreateThread(NULL, 0, thBootScreen, NULL, NULL, 0);

		WaitForMultipleObjects(2, hTH, TRUE, INFINITE);
	}

	return bT;
}

static WCHAR l_szConsoleTitle[] = L"[_rift-Loader] by Lima X [L4X] | (debug/dev-build)";
static DWORD WINAPI thConsoleTitle(
	_In_ PVOID pParam
) {
	UNREFERENCED_PARAMETER(pParam);
	PWCHAR pTitleBuf = AllocMemory(sizeof(l_szConsoleTitle));
	if (pTitleBuf) {
		ZeroMemory((PBYTE)pTitleBuf, sizeof(l_szConsoleTitle));
		for (UINT8 i = 0; i < sizeof(l_szConsoleTitle) / sizeof(WCHAR); i++) {
			pTitleBuf[i] = l_szConsoleTitle[i];
			SetConsoleTitleW(pTitleBuf);
			Sleep(50);
		}
	}

	return 0;
}

static PCWSTR l_szRiftLogo[] = {
	L"             __  _____  __      ____       __________   ____ ",
	L"     _______|__|/ ____\\/  |_   |   _|      \\______   \\ |_   |",
	L"     \\_  __ \\  \\   __\\\\   __\\  |  |         |       _/   |  |",
	L"      |  | \\/  ||  |   |  |    |  |         |    |   \\   |  |",
	L" _____|__|  |__||__|   |__|    |  |_   _____|____|_  /  _|  |",
	L"/_____/                        |____| /_____/      \\/  |____|"
};
static DWORD WINAPI thBootScreen(
	_In_ PVOID pParam
) {
	UNREFERENCED_PARAMETER(pParam);
	WCHAR** rift = AllocMemory(6 * 61 * sizeof(WCHAR));
	for (UINT8 i = 0; i < 6; i++)
		CopyMemory((PWCHAR)rift + (61 * i), l_szRiftLogo[i], 61 * sizeof(WCHAR));

	SetConsoleTextAttribute(l_hCon, CON_ERROR);
	BOOLEAN bDone = FALSE;
	DWORD dwWritten;
	while (!bDone) {
		UINT8 x = ERandomIntDistribution(NULL, 0, 60);
		UINT8 y = ERandomIntDistribution(NULL, 0, 5);

		if (((PWCHAR)rift + (61 * y))[x] != L' ') {
			SetConsoleCursorPosition(l_hCon, (COORD){ x, y });
			WriteConsoleW(l_hCon, &((PWCHAR)rift + (61 * y))[x], 1, &dwWritten, NULL);
			((PWCHAR)rift + (61 * y))[x] = L' ';
			Sleep(10);
		} else {
			bDone = TRUE;
			for (UINT8 i = 0; i < 6; i++)
				for (UINT8 j = 0; j < 61; j++)
					if (((PWCHAR)rift + (61 * i))[j] != L' ')
						bDone = FALSE;
		}
	}

	SetConsoleTextAttribute(l_hCon, CON_INFO);
	SetConsoleCursorPosition(l_hCon, (COORD) { 0, 6 });
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(l_hCon, &csbi);
	for (UINT16 i = 0; i < csbi.dwSize.X; i++) {
		WriteConsoleW(l_hCon, L"=", 1, &dwWritten, NULL);
		Sleep(10);
	}

	return 0;
}

VOID fnCLS(
	_In_ HANDLE hConsole
) {
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
		return;

	DWORD dwConSize = csbi.dwSize.X * csbi.dwSize.Y;
	COORD coordScreen = { 0, 0 };
	DWORD cCharsWritten;
	if (!FillConsoleOutputCharacterW(hConsole, L' ', dwConSize, coordScreen, &cCharsWritten))
		return;
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
		return;
	if (!FillConsoleOutputAttribute(hConsole, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten))
		return;

	SetConsoleCursorPosition(hConsole, coordScreen);
}

BOOL fnPrintF(PCWSTR pText, WORD wAttribute, ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);

	PVOID hBuf = AllocMemory(0x1000);
	SIZE_T nBufLen;
	StringCchVPrintfW((STRSAFE_LPWSTR)hBuf, 0x1000 / sizeof(WCHAR), pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)hBuf, 0x1000 / sizeof(WCHAR), &nBufLen);
	SetConsoleTextAttribute(l_hCon, wAttribute);
	WriteConsoleW(l_hCon, hBuf, nBufLen, &nBufLen, NULL);
	FreeMemory(hBuf);

	va_end(vaArg);
	return nBufLen;
}