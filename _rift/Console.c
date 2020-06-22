#include "pch.h"
#include "_rift.h"

static DWORD WINAPI thConsoleTitle(_In_ PVOID pParam);
static DWORD WINAPI thBootScreen(_In_ PVOID pParam);
static HANDLE l_hCon;

BOOL IOpenConsole() {
	BOOL bT = AllocConsole();
	if (bT) {
		l_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
		HANDLE hTH[2];
		hTH[0] = CreateThread(0, 0, thConsoleTitle, 0, 0, 0);
		hTH[1] = CreateThread(0, 0, thBootScreen, 0, 0, 0);

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
	L"/_____/                        |____| /_____/      \\/  |____|",
};
static DWORD WINAPI thBootScreen(
	_In_ PVOID pParam
) {
	UNREFERENCED_PARAMETER(pParam);
	BOOL bDone = 0b111111;
	UINT8 ui8I[6] = { 0 };
	DWORD dwWritten;
	while (bDone) {
		UINT8 ui8R = (UINT8)ERandomIntDistribution(0, 0, 5);

		if ((bDone >> ui8R) & 0b1) {
			SetConsoleCursorPosition(l_hCon, (COORD){ ui8I[ui8R], ui8R });
			WriteConsoleW(l_hCon, &l_szRiftLogo[ui8R][ui8I[ui8R]], 1, &dwWritten, 0);

			if (ui8I[ui8R] == 61)
				bDone &= ~(0b1 << ui8R);
			else
				ui8I[ui8R]++;

			Sleep(10);
		}
	}

	SetConsoleCursorPosition(l_hCon, (COORD) { 0, 6 });
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(l_hCon, &csbi);
	for (UINT16 i = 0; i < csbi.dwSize.X; i++) {
		WriteConsoleW(l_hCon, L"=", 1, &dwWritten, 0);
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
	WriteConsoleW(l_hCon, hBuf, nBufLen, &nBufLen, 0);
	FreeMemory(hBuf);

	va_end(vaArg);
	return nBufLen;
}