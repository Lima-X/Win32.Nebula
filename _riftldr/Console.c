#include "_riftldr.h"

// Console Output/Input Handle
STATIC HANDLE l_hCO;
STATIC HANDLE l_hCI;

CONST STATIC PCWSTR l_szRiftLogo[] = {
	L"             __  _____  __   __        ___       ",
	L"     _______|__|/ ____\\/  |_|  |    __| _/______ ",
	L"     \\_  __ \\  \\   __\\\\   __\\  |   / __ |\\_  __ \\",
	L"      |  | \\/  ||  |   |  | |  |__/ /_/ | |  | \\/",
	L" _____|__|  |__||__|   |__| |____/\\____ | |__|   ",
	L"/_____/                                \\/        "
};
CONST STATIC PCWSTR l_szRiftInfo[] = {
	L"[_rift V1] coded by [Lima X]\n",
	L"\n",
	L"Special Thanks to:\n",
	L"[irql](Chris) : helping with Wintrnls\n",
	L"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
	L"Testxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
};
BOOL IOpenConsole() {
	BOOL bT = AllocConsole();
	if (!bT)
		return 0;

	SetConsoleTitleW(L"[_riftldr] (debug / dev-build)");
	l_hCO = GetStdHandle(STD_OUTPUT_HANDLE);
	l_hCI = GetStdHandle(STD_OUTPUT_HANDLE);

	{	// Make Cursor invisible
		CONSOLE_CURSOR_INFO cci;
		GetConsoleCursorInfo(l_hCO, &cci);
		cci.bVisible = FALSE;
		// SetConsoleCursorInfo(l_hCO, &cci);
	}

	// Get width of riftLogo
	SIZE_T nRiftLogo;
	StringCchLengthW(*l_szRiftLogo, STRSAFE_MAX_LENGTH, &nRiftLogo);

	{	// Set Console Size
		// Get width of riftInfo
		SIZE_T nRiftInfo = 0;
		for (UINT8 i = 0; i < 6; i++) {
			SIZE_T nT;
			StringCchLengthW(l_szRiftInfo[i], STRSAFE_MAX_LENGTH, &nT);
			if (nT > nRiftInfo)
				nRiftInfo = nT - 1;
		}

		CONSOLE_FONT_INFO cfi;
		GetCurrentConsoleFont(l_hCO, FALSE, &cfi);
		COORD coWnd;
		coWnd.X = (nRiftLogo + nRiftInfo + 9) * cfi.dwFontSize.X + 1;
		coWnd.Y = (0 + 10) * cfi.dwFontSize.Y - 9;
		HWND wndCon = GetConsoleWindow();
		SetWindowPos(wndCon, NULL, 0, 0, coWnd.X, coWnd.Y, SWP_NOMOVE);
	}

	{	// Print Boarders
		SetConsoleTextAttribute(l_hCO, CON_INFO);
		SetConsoleCursorPosition(l_hCO, (COORD) { 0, 6 });
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(l_hCO, &csbi);
		DWORD dwWritten;
		for (SHORT i = 0; i < csbi.dwSize.X; i++) {
			if (i > (nRiftLogo + 2) && i <= (nRiftLogo + 8 * 2) && !((i - (nRiftLogo + 2)) % 2)) {
				CONSOLE_SCREEN_BUFFER_INFO csbiT;
				GetConsoleScreenBufferInfo(l_hCO, &csbiT);
				SetConsoleCursorPosition(l_hCO, (COORD) { nRiftLogo + 2, 6 - ((i - (nRiftLogo + 2)) / 2) });
				WriteConsoleW(l_hCO, L"|", 1, &dwWritten, NULL);
				SetConsoleCursorPosition(l_hCO, csbiT.dwCursorPosition);
			} if (i == (nRiftLogo + 2))
				WriteConsoleW(l_hCO, L"+", 1, &dwWritten, NULL);
			else
				WriteConsoleW(l_hCO, L"-", 1, &dwWritten, NULL);
			Sleep(10);
		}
	}

	// Get Number of Char's in riftLogo
	UINT uRLC = 0;
	for (UINT8 i = 0; i < 6; i++)
		for (UINT j = 0; j < nRiftLogo; j++)
			if (l_szRiftLogo[i][j] != L' ')
				uRLC++;
	// Get Number of Char's in riftInfo
	UINT uRIC = 0;
	for (UINT8 i = 0; i < 6; i++) {
		SIZE_T nT;
		StringCchLengthW(l_szRiftInfo[i], STRSAFE_MAX_LENGTH, &nT);
		uRIC += nT;
	}

	// Copy riftLogo into rawDataFormat
	PWCHAR riftLogo = AllocMemory(6 * nRiftLogo * sizeof(WCHAR));
	for (UINT8 i = 0; i < 6; i++)
		CopyMemory(riftLogo + (nRiftLogo * i), l_szRiftLogo[i], nRiftLogo * sizeof(WCHAR));
	// Copy riftInfo into rawDataFormat
	PWCHAR riftInfo = AllocMemory(uRIC * sizeof(WCHAR));
	{
		PWCHAR riftInfoC = riftInfo;
		for (UINT8 i = 0; i < 6; i++) {
			SIZE_T nT;
			StringCchLengthW(l_szRiftInfo[i], STRSAFE_MAX_LENGTH, &nT);
			CopyMemory(riftInfoC, l_szRiftInfo[i], nT * sizeof(WCHAR));
			riftInfoC += nT;
		}
	}
	SetConsoleTextAttribute(l_hCO, CON_ERROR);
	SetConsoleCursorPosition(l_hCO, (COORD) { nRiftLogo + 4, 0 });
	for (UINT i = 0; i < uRLC * uRIC; i++) {
		BOOLEAN bSleep = FALSE;
		if (!(i % (uRLC + 0))) { // Print riftInfo
			STATIC BOOLEAN bFirst = TRUE;
			STATIC UINT uPos = 0;
			STATIC CONSOLE_SCREEN_BUFFER_INFO csbi;
			if (!bFirst)
				SetConsoleCursorPosition(l_hCO, csbi.dwCursorPosition);
			else
				bFirst = FALSE;

			DWORD dwWritten;
			if (riftInfo[uPos] != L'\n')
				WriteConsoleW(l_hCO, &riftInfo[uPos], 1, &dwWritten, NULL);

			GetConsoleScreenBufferInfo(l_hCO, &csbi);
			if (riftInfo[uPos] == L'\n') {
				if (csbi.dwCursorPosition.Y < 5)
					csbi.dwCursorPosition.Y++;
				csbi.dwCursorPosition.X = nRiftLogo + 4;
			}

			uPos++;
			bSleep = TRUE;
		} if (!(i % uRIC)) { // Print riftLogo
			BOOLEAN bRetry = TRUE;
			do {
				SHORT x = ERandomIntDistribution(NULL, 0, nRiftLogo - 1);
				SHORT y = ERandomIntDistribution(NULL, 0, 5);

				if ((riftLogo + (nRiftLogo * y))[x] != L' ') {
					SetConsoleCursorPosition(l_hCO, (COORD) { x + 1, y });
					DWORD dwWritten;
					WriteConsoleW(l_hCO, &(riftLogo + (nRiftLogo * y))[x], 1, &dwWritten, NULL);
					(riftLogo + (nRiftLogo * y))[x] = L' ';
					bRetry = FALSE;
				}
			} while (bRetry);
			bSleep = TRUE;
		} if (bSleep)
			Sleep(10);
	}

	FreeMemory(riftLogo);
	FreeMemory(riftInfo);
	return bT;
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

// TODO: rewritte this shit
BOOL fnPrintF(PCWSTR pText, WORD wAttribute, ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);

	PVOID hBuf = AllocMemory(0x1000);
	SIZE_T nBufLen;
	StringCchVPrintfW((STRSAFE_LPWSTR)hBuf, 0x1000 / sizeof(WCHAR), pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)hBuf, 0x1000 / sizeof(WCHAR), &nBufLen);
	SetConsoleTextAttribute(l_hCO, wAttribute);
	WriteConsoleW(l_hCO, hBuf, nBufLen, &nBufLen, NULL);
	FreeMemory(hBuf);

	va_end(vaArg);
	return nBufLen;
}