#include "_riftldr.h"

// Console Output/Input Handle
static HANDLE l_hCO;
static HANDLE l_hCI;

const static PCWSTR l_szRiftLogo[] = {
	L"             __  _____  __   __        ___       ",
	L"     _______|__|/ ____\\/  |_|  |    __| _/______ ",
	L"     \\_  __ \\  \\   __\\\\   __\\  |   / __ |\\_  __ \\",
	L"      |  | \\/  ||  |   |  | |  |__/ /_/ | |  | \\/",
	L" _____|__|  |__||__|   |__| |____/\\____ | |__|   ",
	L"/_____/                                \\/        "
};
const static PCWSTR l_szRiftInfo[] = {
	L"[_rift V1] coded by [Lima X]\n",
	L"\n",
	L"Special Thanks to:\n",
	L"[irql](Chris) : helping with Wintrnls\n",
	L"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
	L"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
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
		SetConsoleCursorInfo(l_hCO, &cci);
	}

	// Get width of riftLogo
	size_t nRiftLogo;
	StringCchLengthW(*l_szRiftLogo, STRSAFE_MAX_LENGTH, &nRiftLogo);

	{	// Set Console Size
		// Get width of riftInfo
		size_t nRiftInfo = 0;
		for (uchar i = 0; i < 6; i++) {
			size_t nT;
			StringCchLengthW(l_szRiftInfo[i], STRSAFE_MAX_LENGTH, &nT);
			if (nT > nRiftInfo)
				nRiftInfo = nT - 1;
		}

		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(l_hCO, &csbi);
		SMALL_RECT sr;
		ZeroMemory(&sr, sizeof(SHORT) * 2);

		sr.Right = (nRiftLogo + nRiftInfo + 4);
		sr.Bottom = (0 + 7) - 1;
		if (sr.Right < csbi.srWindow.Right) {
			SetConsoleWindowInfo(l_hCO, TRUE, &sr);
			SetConsoleScreenBufferSize(l_hCO, { sr.Right + 1, csbi.dwSize.Y });
		} else if (sr.Right > csbi.srWindow.Right) {
			SetConsoleScreenBufferSize(l_hCO, { sr.Right + 1, csbi.dwSize.Y });
			SetConsoleWindowInfo(l_hCO, TRUE, &sr);
		} else {
			SetConsoleWindowInfo(l_hCO, TRUE, &sr);
		}

	}

	{	// Print Boarders
		SetConsoleTextAttribute(l_hCO, CON_INFO);
		SetConsoleCursorPosition(l_hCO, { 0, 6 });
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(l_hCO, &csbi);
		dword dwWritten;
		for (SHORT i = 0; i < csbi.dwSize.X; i++) {
			if (i > (nRiftLogo + 2) && i <= (nRiftLogo + 8 * 2) && !((i - (nRiftLogo + 2)) % 2)) {
				CONSOLE_SCREEN_BUFFER_INFO csbiT;
				GetConsoleScreenBufferInfo(l_hCO, &csbiT);
				SetConsoleCursorPosition(l_hCO, { (short)nRiftLogo + 2, (short)(6 - ((i - (nRiftLogo + 2)) / 2)) });
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
	uint uRLC = 0;
	for (uchar i = 0; i < 6; i++)
		for (uint j = 0; j < nRiftLogo; j++)
			if (l_szRiftLogo[i][j] != L' ')
				uRLC++;
	// Get Number of Char's in riftInfo
	uint uRIC = 0;
	for (uchar i = 0; i < 6; i++) {
		size_t nT;
		StringCchLengthW(l_szRiftInfo[i], STRSAFE_MAX_LENGTH, &nT);
		uRIC += nT;
	}

	// Copy riftLogo into rawDataFormat
	wchar* riftLogo = (wchar*)malloc(6 * nRiftLogo * sizeof(WCHAR));
	for (uchar i = 0; i < 6; i++)
		CopyMemory(riftLogo + (nRiftLogo * i), l_szRiftLogo[i], nRiftLogo * sizeof(WCHAR));
	// Copy riftInfo into rawDataFormat
	wchar* riftInfo = (wchar*)malloc(uRIC * sizeof(WCHAR));
	{
		wchar* riftInfoC = riftInfo;
		for (uchar i = 0; i < 6; i++) {
			size_t nT;
			StringCchLengthW(l_szRiftInfo[i], STRSAFE_MAX_LENGTH, &nT);
			CopyMemory(riftInfoC, l_szRiftInfo[i], nT * sizeof(WCHAR));
			riftInfoC += nT;
		}
	}

	SetConsoleTextAttribute(l_hCO, CON_ERROR);
	for (uint i = 0; i < uRLC * uRIC; i++) {
		BOOLEAN bSleep = FALSE;
		if (!(i % uRIC)) { // Print riftLogo
			BOOLEAN bRetry = TRUE;
			do {
				SHORT x = rng::Xoshiro::Instance()->ERandomIntDistribution(0, nRiftLogo - 1);
				SHORT y = rng::Xoshiro::Instance()->ERandomIntDistribution(0, 5);

				if ((riftLogo + (nRiftLogo * y))[x] != L' ') {
					SetConsoleCursorPosition(l_hCO, { x + 1, y });
					dword dwWritten;
					WriteConsoleW(l_hCO, &(riftLogo + (nRiftLogo * y))[x], 1, &dwWritten, NULL);
					(riftLogo + (nRiftLogo * y))[x] = L' ';
					bRetry = FALSE;
				}
			} while (bRetry);
			bSleep = TRUE;
		} if (!(i % (uRLC + 0))) { // Print riftInfo
			static BOOLEAN bFirst = TRUE;
			static uint uPos = 0;
			static CONSOLE_SCREEN_BUFFER_INFO csbi;
			if (!bFirst)
				SetConsoleCursorPosition(l_hCO, csbi.dwCursorPosition);
			else {
				SetConsoleCursorPosition(l_hCO, { (short)nRiftLogo + 4, 0 });
				bFirst = FALSE;
			}

			dword dwWritten;
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
		} if (bSleep)
			Sleep(10);
	}
	free(riftLogo);
	free(riftInfo);

	{	// Extend Window
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(l_hCO, &csbi);
		SMALL_RECT sr;
		ZeroMemory(&sr, sizeof(SHORT) * 2);

		sr.Right = csbi.srWindow.Right;
		sr.Bottom = (10 + 7);
		SetConsoleWindowInfo(l_hCO, TRUE, &sr);
	}

	SetConsoleCursorPosition(l_hCO, { 0, 7 });
	return bT;
}

VOID fnCLS(
	_In_ HANDLE hConsole
) {
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
		return;

	dword dwConSize = csbi.dwSize.X * csbi.dwSize.Y;
	COORD coordScreen = { 0, 0 };
	dword cCharsWritten;
	if (!FillConsoleOutputCharacterW(hConsole, L' ', dwConSize, coordScreen, &cCharsWritten))
		return;
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
		return;
	if (!FillConsoleOutputAttribute(hConsole, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten))
		return;

	SetConsoleCursorPosition(hConsole, coordScreen);
}

status EPrintFW(
	_In_     PCWSTR pText,
	_In_opt_ WORD   wAttribute,
	_In_opt_ ...
) {
	va_list vaArg;
	va_start(vaArg, wAttribute);

	void* hBuf = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	size_t nBufLen;
	if (!hBuf)
		return -1;

	StringCchVPrintfW((STRSAFE_LPWSTR)hBuf, 0x800, pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)hBuf, 0x800, &nBufLen);
	if (wAttribute)
		SetConsoleTextAttribute(l_hCO, wAttribute);
	WriteConsoleW(l_hCO, hBuf, nBufLen, (dword*)&nBufLen, NULL);
	VirtualFree(hBuf, 0, MEM_RELEASE);

	va_end(vaArg);
	return nBufLen;
}