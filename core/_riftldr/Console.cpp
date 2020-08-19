#include "_riftldr.h"

/* Current ui layout/design:
    Logo | Info
   ------+------
   Text

   -------------------

   New planned design:
   +-------+-----+
   | Logo / Info |
   +-----+-------+
   | TextText    |
   | Text        |
   +-------------+

   Animation points:
   1>a-----2>----3
   b      d      e
   2>c---3>------4
   | Text        |
   3>------------5

   a good way would to do this animated would be by making line drawing functions,
   that take in a callback and giving the those a context about position etc, then letting the callback handle what to do.
   to do stuff asynchronously i would use threads, each one drawing a specific line,
   and a hostthread(clock) that would notify all threads when to draw a symbol
   (the clock would be a bit overkill tho ig and small mismatches wouldn't visible anyways)

   best found solution for async printing is an initial launch of the first line and a "master callback".
   this master callback is used from every thread and every draw line function,
   its given context from which fucntion and which part of the animation it was called from,
   together with this information and the coords of the currect drawing position,
   the callback will decide on what to do and how to respond.
   these actions may include: launching extra threads, writing to the CSB and basically anything else.

   WriteConsoleOutput can be used to scroll the text inside the drawn box by repasting the rows

   Full Scale new ui:
     |--- dynamically calculated at runtime ---------------| |--- dynamically calculated at runtime -----------|
    +-------------------------------------------------------+---------------------------------------------------+
	|              __  _____  __   __        ___           / [_rift V1] coded by [Lima X]                       | -
	|      _______|__|/ ____\/  |_|  |    __| _/______    / A random selected Slogan followed by an empty line  | |
	|      \_  __ \  \   __\\   __\  |   / __ |\_  __ \  /                                                      | | 6chars semi
	|       |  | \/  ||  |   |  | |  |__/ /_/ | |  | \/ / Special Thanks to:                                    | | hardcoded
	|  _____|__|  |__||__|   |__| |____/\____ | |__|   / [irql](Chris) : helping with Wintrnls                  | |
	| /_____/                                \/       / and a lot more in the future probably :flushed:         | -
	+------------------------------------------------+----------------------------------------------------------+
	| Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore | -
	| et dolore magna aliquyam erat, sed diam voluptua.                                                         | |
	| At vero eos et accusam et justo duo dolores et ea rebum.                                                  | | definable
	|                                                                                                           | | in software
	| Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.                        | |
	|                                                                                                           | -
	+-----------------------------------------------------------------------------------------------------------+
*/

#define LOGOINTERSECT 0

namespace cui {
	static const char* l_szRiftLogo[] = {
		"             __  _____  __   __        ___",
		"     _______|__|/ ____\\/  |_|  |    __| _/______",
		"     \\_  __ \\  \\   __\\\\   __\\  |   / __ |\\_  __ \\",
		"      |  | \\/  ||  |   |  | |  |__/ /_/ | |  | \\/",
		" _____|__|  |__||__|   |__| |____/\\____ | |__|",
		"/_____/                                \\/"
	};
	struct RiftLogoRaw {
		uint8 nWidth;
		uint16 nChars;
		struct riftLogoFormat {
			char c;
			struct {
				uchar x;
				uchar y;
			} sPos;
		} *aData;

		RiftLogoRaw()
			: nWidth(0), nChars(0)
		{
			{	// Get width and number of chars in riftLogo
				for (uint8 i = 0; i < 6; i++) {
					uint8 n = strlen(l_szRiftLogo[i]);
					if (n > nWidth)
						nWidth = n;
				}
				for (uint8 i = 0; i < 6; i++) {
					uint8 nWidth = strlen(l_szRiftLogo[i]);
					for (uint8 j = 0; j < nWidth; j++)
						if (l_szRiftLogo[i][j] != ' ')
							nChars++;
				}
			}

			// Allocate riftLogoInformation Array and Initialize
			aData = (riftLogoFormat*)malloc(nChars * sizeof(riftLogoFormat));
			uint16 nIndex = 0;
			for (uint8 i = 0; i < 6; i++) {
				uint8 nWidth = strlen(l_szRiftLogo[i]);
				for (uint8 j = 0; j < nWidth; j++)
					if (l_szRiftLogo[i][j] != ' ') {
						aData[nIndex].c = l_szRiftLogo[i][j];
						aData[nIndex].sPos = { j, i };
						nIndex++;
					}
			}

			// Shuffle Array (20 Rounds)
			for (uint32 i = 0; i < nIndex * 20; i++) {
				uint16 n1 = rng::Xoshiro::Instance()->ERandomIntDistribution(0, nIndex - 1);
				uint16 n2 = rng::Xoshiro::Instance()->ERandomIntDistribution(0, nIndex - 1);
				if (n1 == n2) // might remove this, branching might just make it slower
					continue;

				{	// Swap Elements
					riftLogoFormat rlf = aData[n1];
					aData[n1] = aData[n2];
					aData[n2] = rlf;
				}
			}
		}
		~RiftLogoRaw() {
			free(aData);
		}
	};

	static const char* l_szRiftSlogan[] = {
		"A very bad UX.",
		"Come at me, I know you won't.",
		"nyan nyan nyan nyan nyan",
		"std::string == bytearray ~gui",
		"You will regret this...",
		"batch and vbs == real shit!",
		"I was here before I think, wasn't I ?",
		"Im your systems DooM :D",
		"Thank your for choosing _rift !",
		"You fell for it, YOU IDIOT !",
		"Fucking your system 24/7",
		"listen here you little fag.",
		"0xC0000374, your favourite Error.",
		"Ima snipp of your Foreskin !",
		"Segmentation fault. (core dumped)",
		"A randomly selected Slogan",
		"Rush B, CUNT",
		"This is a Nightmare, but for your System.",

	};
	static const char* l_szRiftInfo[] = {
		"[_rift V1] coded by [Lima X]\n",
		// A random selected Slogan followed by an empty line
		"Special Thanks to:\n"
		"[irql](Chris) : helping with Wintrnls\n"
		"and a lot more in the future probably :flushed:"
	};
	struct RiftInfoRaw {
		uint8 nWidth;
		uint16 nLength;
		char* aData;

		RiftInfoRaw()
			: nLength(0)
		{
			// Choose Random Slogan
			uint8 iSlogan = rng::Xoshiro::Instance()->ERandomIntDistribution(0, (sizeof(l_szRiftSlogan) / sizeof(*l_szRiftSlogan)) - 1);

			// Get Maximum width (-slant) of riftInfo
			nWidth = strlen(l_szRiftInfo[0]) - 1; // minus newline char
			{
				uint8 n = strlen(l_szRiftSlogan[iSlogan]);
				if (n - 1 > nWidth) // account for slant
					nWidth = n - 1;
			}
			for (uchar i = 0; i < 3; i++) {
				static uint16 offset = 0;
				for (uint8 j = 0; *(l_szRiftInfo[1] + offset) != '\n' && *(cui::l_szRiftInfo[1] + offset) != '\0'; j++) {
					if (j - (i + 3) > nWidth) // account for slant
						nWidth = j - (i + 3);
					offset += j + 1;
				}
			}

			// Get length, allocate and generate raw Data
			nLength = strlen(l_szRiftInfo[0]);
			nLength += strlen(l_szRiftSlogan[iSlogan]) + 2;
			nLength += strlen(l_szRiftInfo[1]);
			aData = (char*)malloc(nLength + 1);
			strcpy(aData, l_szRiftInfo[0]);
			strcat(aData, l_szRiftSlogan[iSlogan]);
			strcat(aData, "\n\n");
			strcat(aData, l_szRiftInfo[1]);
		}
		~RiftInfoRaw() {
			free(aData);
		}
	};

	struct RawContext {
		RiftLogoRaw* rlr;
		RiftInfoRaw* rir;
	};

	namespace cgl {
		struct GContext {
			HANDLE hConOut;
			enum gType {
				HORIZONTAL,
				VERTICAL,
				LEFTSLANT,
				// RIGHTSLANT not to be implemented, as it is not needed
			} call;
			COORD cord1;
			short p2;
			wchar(*Callback)(
				_In_ COORD     cord,
				_In_ GContext& ctx
				);
			void* ctx;
			bool bRead = false; // this Flag is set to true after the thread created a local copy
		};

		// This fucntion seriously has to be cleaned up
		dword WINAPI DrawLine(
			_In_ void* pParm
		) {
			GContext ctx = *(GContext*)pParm;
			((GContext*)pParm)->bRead = true;

			auto PrintCharWL = [&](
				_In_ COORD cord,
				_In_ wchar c
				) {
					if (!c) {
						switch (ctx.call) {
						case GContext::gType::HORIZONTAL:
							if (cord.X != ctx.cord1.X && cord.X != ctx.p2)
								c = L'-';
							break;
						case GContext::gType::VERTICAL:
							if (cord.Y != ctx.cord1.Y && cord.Y != ctx.p2)
								c = L'|';
							break;
						case GContext::gType::LEFTSLANT:
							if (cord.Y != ctx.cord1.Y && cord.Y != ctx.p2)
								c = L'/';
						}
						if (!c)
							c = L'+';
					}
					dword dw;
					WriteConsoleOutputCharacterW(ctx.hConOut, &c, 1, cord, &dw);
			};

			switch (ctx.call) {
			case GContext::gType::HORIZONTAL: // Left to Right
				for (short i = ctx.cord1.X; i <= ctx.p2; i++)
					PrintCharWL({ i , ctx.cord1.Y }, ctx.Callback({ i , ctx.cord1.Y }, ctx));
				break;
			case GContext::gType::VERTICAL: // Top to Bottom
				for (short i = ctx.cord1.Y; i <= ctx.p2; i++)
					PrintCharWL({ ctx.cord1.X, i }, ctx.Callback({ ctx.cord1.X, i }, ctx));
				break;
			case GContext::gType::LEFTSLANT: // Bottom to Top
				for (short i = ctx.cord1.Y; i >= ctx.p2; i--)
					PrintCharWL({ (ctx.cord1.X + (ctx.cord1.Y - ctx.p2)) - i , i }, ctx.Callback({ (ctx.cord1.X + (ctx.cord1.Y - ctx.p2)) - i , i }, ctx));
				break;
			default:
				return 1; // Indicate Error
			}
			return 0;
		}

#if 0 // Deprecated use DrawLine
		dword WINAPI DrawHorizontalLine(
			_In_ GContext* ctx
		) {
			for (short i = ctx->cord.X; i < ctx->x2; i++) {
				wchar wc = ctx->Callback({ i , ctx->cord.Y }, ctx->Context);
				dword dw;
				WriteConsoleOutputCharacterW(ctx->hConOut, &wc, 1, { i , ctx->cord.Y }, &dw);
			}
			return 0;
		}
		dword WINAPI DrawVerticalLine(
			_In_ GContext* ctx
		) {
			for (short i = ctx->cord.Y; i < ctx->y2; i++) {
				wchar wc = ctx->Callback({ ctx->cord.X, i }, ctx->Context);
				dword dw;
				WriteConsoleOutputCharacterW(ctx->hConOut, &wc, 1, { ctx->cord.X, i }, &dw);
			}
			return 0;
		}
		dword WINAPI DrawSlantLeftLine(
			_In_ GContext* ctx
		) {
			for (short i = ctx->cord.Y; i < ctx->y2; i++) {
				wchar wc = ctx->Callback({ ctx->cord.X - i , i }, ctx->Context);
				dword dw;
				WriteConsoleOutputCharacterW(ctx->hConOut, &wc, 1, { ctx->cord.X - i , i }, &dw);
			}
			return 0;
		}
#endif

		wchar GLCallBack(
			_In_ COORD     cord,
			_In_ GContext& ctx
		) {
			RawContext* uctx = (RawContext*)ctx.ctx;

			const COORD points[] = {
				{ uctx->rlr->nWidth - LOGOINTERSECT, 7 },
				{ 0, 7 },
				{ uctx->rlr->nWidth + uctx->rir->nWidth + 4 - LOGOINTERSECT, 0 },
				{ 0, 20 },
			};
			uint8 iIndex = -1;
			for (uint8 i = 0; i < sizeof(points) / sizeof(*points); i++)
				if (*(dword*)&cord == *(dword*)&points[i]) {
					iIndex = i;
					break;
				}

			if (ctx.call == GContext::gType::HORIZONTAL)
				Sleep(50);
			else
				Sleep(100);

			switch (iIndex) {
			case 0: {
				if (ctx.call != GContext::gType::HORIZONTAL)
					return 0;
				GContext a = ctx;
				a.call = a.LEFTSLANT;
				a.cord1 = points[iIndex];
				a.p2 = 0;
				HANDLE hThread = CreateThread(nullptr, 0, (PTHREAD_START_ROUTINE)DrawLine, &a, NULL, nullptr);
				while (!a.bRead);
				CloseHandle(hThread);
			} break;
			case 1: {
				if (ctx.call != GContext::gType::VERTICAL)
					return 0;
				GContext a = ctx;
				a.call = a.HORIZONTAL;
				a.cord1 = points[iIndex];
				a.p2 = uctx->rlr->nWidth + uctx->rir->nWidth + 4 - LOGOINTERSECT;
				HANDLE hThread = CreateThread(nullptr, 0, (PTHREAD_START_ROUTINE)DrawLine, &a, NULL, nullptr);
				while (!a.bRead);
				CloseHandle(hThread);
				return L'x';
			}
			case 2: {
				if (ctx.call != GContext::gType::HORIZONTAL)
					return 0;
				GContext a = ctx;
				a.call = a.VERTICAL;
				a.cord1 = points[iIndex];
				a.p2 = 20;
				HANDLE hThread = CreateThread(nullptr, 0, (PTHREAD_START_ROUTINE)DrawLine, &a, NULL, nullptr);
				while (!a.bRead);
				CloseHandle(hThread);
				return L'y';
			}
			case 3: {
				if (ctx.call != GContext::gType::VERTICAL)
					return 0;
				GContext a = ctx;
				a.call = a.HORIZONTAL;
				a.cord1 = points[iIndex];
				a.p2 = uctx->rlr->nWidth + uctx->rir->nWidth + 4 - LOGOINTERSECT;
				HANDLE hThread = CreateThread(nullptr, 0, (PTHREAD_START_ROUTINE)DrawLine, &a, NULL, nullptr);
				while (!a.bRead);
				CloseHandle(hThread);
				return L'z';
			}
			}
			return 0;
		}

	}
}

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
		CON_SUCCESS =         FOREGROUND_GREEN,                                         // 0b00000010
		CON_INFO    =         FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,      // 0b00000111
		CON_QUEST   = 0x40 |  FOREGROUND_BLUE | FOREGROUND_INTENSITY,                   // 0b01001001
		CON_ERROR   = 0x80 |  FOREGROUND_RED | FOREGROUND_INTENSITY,                    // 0b10001100
		CON_WARNING = 0x80 | (FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY // 0b10001110
	};

	void PrintIntro() {
		{	// Make Cursor invisible
			CONSOLE_CURSOR_INFO cci;
			GetConsoleCursorInfo(m_hConOut, &cci);
			// cci.bVisible = FALSE;                  disabled for debugging purposes
			SetConsoleCursorInfo(m_hConOut, &cci);
		}

		// Initialize print data
		cui::RiftLogoRaw riftLogo;
		cui::RiftInfoRaw riftInfo;

		{	// Create Rect Info Structure
			CONSOLE_SCREEN_BUFFER_INFO csbi;
			GetConsoleScreenBufferInfo(m_hConOut, &csbi);
			SMALL_RECT sr;
			ZeroMemory(&sr, sizeof(SHORT) * 2);
			sr.Right = (riftLogo.nWidth + riftInfo.nWidth + 4) - LOGOINTERSECT;
			sr.Bottom = (20 + 7) - 1; // 7 Lines

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



		cui::RawContext b;
		b.rlr = &riftLogo;
		b.rir = &riftInfo;

		cui::cgl::GContext a;
		a.hConOut = m_hConOut;
		a.ctx = &b;
		a.Callback = cui::cgl::GLCallBack;

		a.cord1 = { 0, 0 };
		a.p2 = riftLogo.nWidth + riftInfo.nWidth + 4 - LOGOINTERSECT;
		a.call = a.HORIZONTAL;
		HANDLE hThread[2];
		hThread[0] = CreateThread(nullptr, 0, (PTHREAD_START_ROUTINE)cui::cgl::DrawLine, &a, NULL, nullptr);
		while (!a.bRead);

		a.bRead = false;
		a.p2 = 20;
		a.call = a.VERTICAL;
		hThread[1] = CreateThread(nullptr, 0, (PTHREAD_START_ROUTINE)cui::cgl::DrawLine, &a, NULL, nullptr);
		WaitForMultipleObjects(2, hThread, true, INFINITE);
		for (uint8 i = 0; i < 2; i++)
			CloseHandle(hThread[i]);


		Sleep(INFINITE);
#if 0
		{	// Print Layout Boarders
			SetConsoleTextAttribute(m_hConOut, (word)Attributes::CON_INFO & 0xf);
			SetConsoleCursorPosition(m_hConOut, { 0, 6 });
			CONSOLE_SCREEN_BUFFER_INFO csbi;
			GetConsoleScreenBufferInfo(m_hConOut, &csbi);
			dword dwWritten;
			for (uint16 i = 0; i < csbi.dwSize.X; i++) {
				if (i > (riftLogo.nWidth + 2) && i <= (riftLogo.nWidth + 8 * 2) && !((i - (riftLogo.nWidth + 2)) % 2)) {
					// Print vertical Line asynchronously
					CONSOLE_SCREEN_BUFFER_INFO csbiT;
					GetConsoleScreenBufferInfo(m_hConOut, &csbiT);
					SetConsoleCursorPosition(m_hConOut, { riftLogo.nWidth + 2, (short)(6 - ((i - (riftLogo.nWidth + 2)) / 2)) });
					WriteConsoleA(m_hConOut, "|", 1, &dwWritten, NULL);
					SetConsoleCursorPosition(m_hConOut, csbiT.dwCursorPosition);
				} if (i == (riftLogo.nWidth + 2))
					WriteConsoleA(m_hConOut, "+", 1, &dwWritten, NULL); // Print Splitpoint
				else
					WriteConsoleA(m_hConOut, "-", 1, &dwWritten, NULL); // Print horizontal line
				Sleep(10);
			}
		}



		wchar* riftInfo = (wchar*)malloc(riftInfo.nLength * sizeof(WCHAR));
		{
			// Copy riftInfo into rawDataFormat
			wchar* riftInfoC = riftInfo;
			for (uchar i = 0; i < 6; i++) {
				size_t nT = strlen(l_szRiftInfo[i]);
				memcpy(riftInfoC, l_szRiftInfo[i], nT * sizeof(WCHAR));
				riftInfoC += nT;
			}
		}

		// Print Logo and Infotext asynchronously
		for (uint32 i = 0; i < riftLogo.nChars * riftInfo.nLength; i++) {
			uchar bSleep = 0;
			if (!(i % riftInfo.nLength)) { // Print riftLogo
				SetConsoleTextAttribute(m_hConOut, FOREGROUND_RED | FOREGROUND_BLUE); // Purple
				bool bRetry = true;

				// This is an absolute terrible way of randomly printing the Logo,
				// probably the best way would be to generate an Array of Blocks containing the char and its position,
				// then shuffling the array (by swapping elements), i might implement this at somepoint,
				// but i dont care about performance here anyways for obvious reasons...
#if 0
				if ((riftLogo.aData + (nRiftLogoWidth * y))[x] != ' ') {
					SetConsoleCursorPosition(m_hConOut, { x + 1, y });
					dword dwWritten;
					WriteConsoleW(m_hConOut, &(riftLogo.aData + (nRiftLogoWidth * y))[x], 1, &dwWritten, NULL);
					(riftLogo.aData + (nRiftLogoWidth * y))[x] = ' ';
					bRetry = false;
				}
#endif
				bSleep += 10;
			} if (!(i % riftLogo.nChars)) { // Print riftInfo
				SetConsoleTextAttribute(m_hConOut, (word)Attributes::CON_ERROR & 0xf);
				static bool bFirst = true; // probably not the best solution, but this is neccessary to set the start position for the Infotext correctly
				static uint16 uPos = 0;
				static CONSOLE_SCREEN_BUFFER_INFO csbi;
				if (!bFirst)
					SetConsoleCursorPosition(m_hConOut, csbi.dwCursorPosition);
				else {
					SetConsoleCursorPosition(m_hConOut, { (short)nRiftLogoWidth + 4, 0 });
					bFirst = false;
				}

				dword dwWritten;
				if (riftInfo[uPos] != L'\n')
					WriteConsoleW(m_hConOut, &riftInfo[uPos], 1, &dwWritten, NULL);

				GetConsoleScreenBufferInfo(m_hConOut, &csbi);
				if (riftInfo[uPos] == L'\n') {
					if (csbi.dwCursorPosition.Y < 5)
						csbi.dwCursorPosition.Y++;
					csbi.dwCursorPosition.X = nRiftLogoWidth + 4;
				}

				uPos++;
				bSleep += 10;
			} if (bSleep)
				Sleep(bSleep);
		}
		free(riftLogo.aData);
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
#endif
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

		vswprintf((wchar*)m_pBuffer, pText, vaArg);
		m_nBuffer = wcslen((wchar*)m_pBuffer);

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

	// con->PrintFW(L"Test", Console::Attributes::CON_ERROR);
	// con->PrintFW(L"Test, default");
	con->CLS();
	con->PrintIntro();
	con->~Console();

	return 0;
}