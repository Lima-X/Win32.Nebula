#include "_riftldr.h"

static const PCWSTR l_szRiftLogo[] = {
	L"             __  _____  __   __        ___       ",
	L"     _______|__|/ ____\\/  |_|  |    __| _/______ ",
	L"     \\_  __ \\  \\   __\\\\   __\\  |   / __ |\\_  __ \\",
	L"      |  | \\/  ||  |   |  | |  |__/ /_/ | |  | \\/",
	L" _____|__|  |__||__|   |__| |____/\\____ | |__|   ",
	L"/_____/                                \\/        "
};
static const PCWSTR l_szRiftInfo[] = {
	L"[_rift V1] coded by [Lima X]\n",
	L"\n",
	L"Special Thanks to:\n",
	L"[irql](Chris) : helping with Wintrnls\n",
	L"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
	L"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
};

class Console {
public:
	~Console() {
		FreeConsole();
		VirtualFree(m_pBuffer, 0, MEM_RELEASE);
		conInstance = nullptr;
	}
	static Console* Instance() {
		if (!conInstance)
			conInstance = new Console;
		return conInstance;
	}

	enum class Attributes : byte { // most significant bit indecates error type
		CON_SUCCESS = FOREGROUND_GREEN,                                            // 0b00000010
		CON_INFO = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,         // 0b00000111
		CON_QUEST = 0x40 | FOREGROUND_BLUE | FOREGROUND_INTENSITY,                      // 0b01001001
		CON_ERROR = 0x80 | (FOREGROUND_RED | FOREGROUND_INTENSITY),                     // 0b10001100
		CON_WARNING = 0x80 | ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b10001110
	};

	void PrintIntro() {
		{	// Make Cursor invisible
			CONSOLE_CURSOR_INFO cci;
			GetConsoleCursorInfo(m_hConOut, &cci);
			cci.bVisible = FALSE;
			SetConsoleCursorInfo(m_hConOut, &cci);
		}

		// Get width of riftLogo
		size_t nRiftLogo = wcslen(*l_szRiftLogo);

		{	// Get width of riftInfo by getting the longest line
			size_t nRiftInfo = 0;
			for (uchar i = 0; i < 6; i++) {
				size_t nT = wcslen(l_szRiftInfo[i]);
				if (nT > nRiftInfo)
					nRiftInfo = nT;
			}

			// Create Rect Info Structure
			CONSOLE_SCREEN_BUFFER_INFO csbi;
			GetConsoleScreenBufferInfo(m_hConOut, &csbi);
			SMALL_RECT sr;
			ZeroMemory(&sr, sizeof(SHORT) * 2);
			sr.Right = (nRiftLogo + nRiftInfo + 4);
			sr.Bottom = (0 + 7) - 1; // 7 Lines

			// Set Console Window Size
			if (sr.Right < csbi.srWindow.Right) {
				SetConsoleWindowInfo(m_hConOut, true, &sr);
				SetConsoleScreenBufferSize(m_hConOut, { sr.Right + 1, csbi.dwSize.Y });
			} else if (sr.Right > csbi.srWindow.Right) {
				SetConsoleScreenBufferSize(m_hConOut, { sr.Right + 1, csbi.dwSize.Y });
				SetConsoleWindowInfo(m_hConOut, true, &sr);
			} else {
				SetConsoleWindowInfo(m_hConOut, true, &sr);
			}
		}

		{	// Print Layout Boarders
			SetConsoleTextAttribute(m_hConOut, (word)Attributes::CON_INFO & 0xf);
			SetConsoleCursorPosition(m_hConOut, { 0, 6 });
			CONSOLE_SCREEN_BUFFER_INFO csbi;
			GetConsoleScreenBufferInfo(m_hConOut, &csbi);
			dword dwWritten;
			for (ushort i = 0; i < csbi.dwSize.X; i++) {
				if (i > (nRiftLogo + 2) && i <= (nRiftLogo + 8 * 2) && !((i - (nRiftLogo + 2)) % 2)) {
					// Print vertical Line asynchronously
					CONSOLE_SCREEN_BUFFER_INFO csbiT;
					GetConsoleScreenBufferInfo(m_hConOut, &csbiT);
					SetConsoleCursorPosition(m_hConOut, { (short)nRiftLogo + 2, (short)(6 - ((i - (nRiftLogo + 2)) / 2)) });
					WriteConsoleW(m_hConOut, L"|", 1, &dwWritten, NULL);
					SetConsoleCursorPosition(m_hConOut, csbiT.dwCursorPosition);
				} if (i == (nRiftLogo + 2))
					WriteConsoleW(m_hConOut, L"+", 1, &dwWritten, NULL); // Print Splitpoint
				else
					WriteConsoleW(m_hConOut, L"-", 1, &dwWritten, NULL); // Print horizontal line
				Sleep(10);
			}
		}

		ushort uRLC = 0, uRIC = 0;
		{	// Get Number of Char's in riftLogo
			for (uchar i = 0; i < 6; i++)
				for (ushort j = 0; j < nRiftLogo; j++)
					if (l_szRiftLogo[i][j] != L' ')
						uRLC++;
			// Get Number of Char's in riftInfo
			for (uchar i = 0; i < 6; i++)
				uRIC += wcslen(l_szRiftInfo[i]);
		}

		wchar* riftLogo = (wchar*)malloc((6 * nRiftLogo) * sizeof(WCHAR)),
			* riftInfo = (wchar*)malloc(uRIC * sizeof(WCHAR));
		{	// Copy riftLogo into rawDataFormat
			for (uchar i = 0; i < 6; i++)
				memcpy(riftLogo + (nRiftLogo * i), l_szRiftLogo[i], nRiftLogo * sizeof(WCHAR));
			// Copy riftInfo into rawDataFormat
			wchar* riftInfoC = riftInfo;
			for (uchar i = 0; i < 6; i++) {
				size_t nT = wcslen(l_szRiftInfo[i]);
				memcpy(riftInfoC, l_szRiftInfo[i], nT * sizeof(WCHAR));
				riftInfoC += nT;
			}
		}

		// Print Logo and Infotext asynchronously
		for (uint i = 0; i < uRLC * uRIC; i++) {
			uchar bSleep = 0;
			if (!(i % uRIC)) { // Print riftLogo
				SetConsoleTextAttribute(m_hConOut, FOREGROUND_RED | FOREGROUND_BLUE); // Purple
				bool bRetry = true;

				// This is an absolute terrible way of randomly printing the Logo,
				// probably the best way would be to generate an Array of Blocks containing the char and its position,
				// then shuffling the array (by swapping elements), i might implement this at somepoint,
				// but i dont care about performance here anyways for obvious reasons...
				do {
					short x = rng::Xoshiro::Instance()->ERandomIntDistribution(0, nRiftLogo - 1);
					short y = rng::Xoshiro::Instance()->ERandomIntDistribution(0, 5);

					if ((riftLogo + (nRiftLogo * y))[x] != L' ') {
						SetConsoleCursorPosition(m_hConOut, { x + 1, y });
						dword dwWritten;
						WriteConsoleW(m_hConOut, &(riftLogo + (nRiftLogo * y))[x], 1, &dwWritten, NULL);
						(riftLogo + (nRiftLogo * y))[x] = L' ';
						bRetry = false;
					}
				} while (bRetry);
				bSleep += 10;
			} if (!(i % (uRLC + 0))) { // Print riftInfo
				SetConsoleTextAttribute(m_hConOut, (word)Attributes::CON_ERROR & 0xf);
				static bool bFirst = true; // probably not the best solution, but this is neccessary to set the start position for the Infotext correctly
				static ushort uPos = 0;
				static CONSOLE_SCREEN_BUFFER_INFO csbi;
				if (!bFirst)
					SetConsoleCursorPosition(m_hConOut, csbi.dwCursorPosition);
				else {
					SetConsoleCursorPosition(m_hConOut, { (short)nRiftLogo + 4, 0 });
					bFirst = false;
				}

				dword dwWritten;
				if (riftInfo[uPos] != L'\n')
					WriteConsoleW(m_hConOut, &riftInfo[uPos], 1, &dwWritten, NULL);

				GetConsoleScreenBufferInfo(m_hConOut, &csbi);
				if (riftInfo[uPos] == L'\n') {
					if (csbi.dwCursorPosition.Y < 5)
						csbi.dwCursorPosition.Y++;
					csbi.dwCursorPosition.X = nRiftLogo + 4;
				}

				uPos++;
				bSleep += 10;
			} if (bSleep)
				Sleep(bSleep);
		}
		free(riftLogo);
		free(riftInfo);

		{	// Extend Window
			CONSOLE_SCREEN_BUFFER_INFO csbi;
			GetConsoleScreenBufferInfo(m_hConOut, &csbi);
			SMALL_RECT sr;
			ZeroMemory(&sr, sizeof(SHORT) * 2);

			sr.Right = csbi.srWindow.Right;
			sr.Bottom = (10 + 7);
			SetConsoleWindowInfo(m_hConOut, true, &sr);
		}

		SetConsoleCursorPosition(m_hConOut, { 0, 7 });
	}

	status CLS() {
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		if (!GetConsoleScreenBufferInfo(m_hConOut, &csbi))
			return -1;

		dword dwConSize = csbi.dwSize.X * csbi.dwSize.Y;
		COORD coordScreen = { 0, 0 };
		dword cCharsWritten;
		if (!FillConsoleOutputCharacterW(m_hConOut, L' ', dwConSize, coordScreen, &cCharsWritten))
			return -2;
		if (!GetConsoleScreenBufferInfo(m_hConOut, &csbi))
			return -3;
		if (!FillConsoleOutputAttribute(m_hConOut, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten))
			return -4;

		SetConsoleCursorPosition(m_hConOut, coordScreen);
		return 0;
	}


	status WriteW(
		_In_ word   wAttribute
	) {
		if (wAttribute & 0xf)
			SetConsoleTextAttribute(m_hConOut, wAttribute & 0xf);
		// WriteConsoleW(m_hConOut, m_pBuffer, nBufLen, (dword*)&nBufLen, NULL);

	}

	status PrintFW(
		_In_     PCWSTR     pText,
		_In_     Attributes wAttribute = Attributes::CON_INFO,
		_In_opt_            ...
	) {
		va_list vaArg;
		va_start(vaArg, wAttribute);

		vswprintf((wchar_t*)m_pBuffer, (wchar_t*)pText, vaArg);
		m_nBuffer = wcslen((wchar_t*)m_pBuffer);

		va_end(vaArg);
		return m_nBuffer;
	}
private:
	// Constructors are private because its a singleton anyways
	Console(_In_ size_t nBufferSize = 0x1000) {
		if (!AllocConsole())
			return;
		SetConsoleTitleW(L"[_riftldr] (debug / dev-build)");
		m_hConIn = GetStdHandle(STD_INPUT_HANDLE);
		m_hConOut = GetStdHandle(STD_OUTPUT_HANDLE);
		m_hConErr = GetStdHandle(STD_ERROR_HANDLE);  // Optinal

		m_pBuffer = VirtualAlloc(nullptr, nBufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	}

	static Console* conInstance; // Singleton Instance
	void*  m_pBuffer;            // Temporery Buffer (Pool) that will be used to Format, Get Text and more (multiple of Pagesize)
	size_t m_nBuffer;            // The size of data inside the temporery Buffer (Pool)

	// Console Input/Output(/Error) Handle
	HANDLE m_hConIn;
	HANDLE m_hConOut;
	HANDLE m_hConErr; // Optinal
};
Console* Console::conInstance = nullptr;

BOOL IOpenConsole() {
	Console* con = Console::Instance();

	con->PrintFW(L"Test", Console::Attributes::CON_ERROR);
	con->PrintFW(L"Test, default");
	con->CLS();
	con->PrintIntro();
	con->~Console();

	return 0;
}

