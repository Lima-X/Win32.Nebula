#include "shared.h"

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
	| /_____/                                \/       /                                                         | -
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
#define LOGOHEIGHT 6
#define CUIHEIGHT 25
#define ANIMATION_BASESLEEPTIME 25

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
				uint16 n1 = rng::Xoshiro::Instance().RandomIntDistribution(0, nIndex - 1);
				uint16 n2 = rng::Xoshiro::Instance().RandomIntDistribution(0, nIndex - 1);
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
		"_rift, aka. better hDir5.0",
		"This will be living hell >:)",
		"Just give up already, sweatheart <3",
		"a overdose for your system...",
		"It's all just a Game...",
		"_rift will 9/11 your Computer",
		"Please proceed into Android HELL",
		""
	};
	static const char* l_szRiftInfo[] = {
		"[_rift V1] coded by [Lima X]\n",
		// A random selected Slogan followed by an empty line
		"Special Thanks to:\n"
		"[irql](Chris) : helping with Wintrnls\n"
		""
	};
	struct RiftInfoRaw {
		uint8 nWidth;
		uint16 nLength;
		char* aData;

		RiftInfoRaw()
			: nLength(0)
		{
			// Choose Random Slogan
			uint8 iSlogan = rng::Xoshiro::Instance().RandomIntDistribution(0, (sizeof(l_szRiftSlogan) / sizeof(*l_szRiftSlogan)) - 1);

			{	// Get Maximum width (-slant) of riftInfo
				nWidth = strlen(l_szRiftInfo[0]) - 1; // minus newline char
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

	static const char l_szRiftTerms[] = {
		"The Software you are about to run is considered to be Malware !\n"
		"This Malware is capable to and will make changes to the operating System,"
		"these changes include modifications of Files, Registry-Key's, Processes(Memory) and more.\n"
		"THE CREATOR(Lima X) IS NOT RESPONSIBLE FOR ANY HARM/DAMAGE DONE USING THIS SOFTWARE,\n"
		"THE CREATOR IS ALSO NOT RESONSIBLE FOR ANY MODIFICATIONS TO THIS SOFTWARE,\n"
		"THESE MODIFICATIONS MAY INCLUDE THE SUBSEQUENT REMOVAL OF THESE TERMS AND OTHERS.\n"
		"BY RUNNING THIS SOFTWARE YOU AUTOMATICALLY AGREE TO THESE TERMS !\n\n"

		"Note to Cybersecurity-Specialists: This software is melicous and intended only as a Demonstration.\n"
		"                                   If you come across this please just move on and flag it !"
	};
	static const char l_szRiftDisclaimer[] = {
		"This software has been protected through obfuscation, encryption and more.\n"
		"In order to run this please enter the activation Key (form of a UUID),\n"
		"this will also automatically run this Software without the further possibility of stoping it !\n"
		"If you dont know what this is please close this window to exit,\n"
		"If you do know what this is and know the consequenzes involved feel free to continue."
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
					if (c == (wchar)-1)
						return;
					if (!c) {
						switch (ctx.call) {
						case GContext::gType::HORIZONTAL:
							if (cord.X != ctx.cord1.X && cord.X != ctx.p2) c = L'-'; break;
						case GContext::gType::VERTICAL:
							if (cord.Y != ctx.cord1.Y && cord.Y != ctx.p2) c = L'|'; break;
						case GContext::gType::LEFTSLANT:
							if (cord.Y != ctx.cord1.Y && cord.Y != ctx.p2) c = L'/';
						} if (!c)
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

		wchar GLCallBack(
			_In_ COORD     cord,
			_In_ GContext& ctx
		) {
			if (ctx.call == GContext::gType::HORIZONTAL)
				Sleep(ANIMATION_BASESLEEPTIME);
			else
				Sleep(ANIMATION_BASESLEEPTIME * 2);

			RawContext* uctx = (RawContext*)ctx.ctx;
			static const struct Special {
				COORD cord1;
				short p2;
				GContext::gType call;
			} points[] = {
				{ { uctx->rlr->nWidth - LOGOINTERSECT, (LOGOHEIGHT + 2) - 1 }, 0, GContext::gType::LEFTSLANT },
				{ { 0, (LOGOHEIGHT + 2) - 1 },	uctx->rlr->nWidth + uctx->rir->nWidth + 4 - LOGOINTERSECT, GContext::gType::HORIZONTAL },
				{ { uctx->rlr->nWidth + uctx->rir->nWidth + 4 - LOGOINTERSECT, 0 }, CUIHEIGHT - 1, GContext::gType::VERTICAL },
				{ { uctx->rlr->nWidth + uctx->rir->nWidth + 4 - LOGOINTERSECT, (LOGOHEIGHT + 2) - 1 }, NULL, (GContext::gType)NULL },
				{ { 0, CUIHEIGHT - 1 }, uctx->rlr->nWidth + uctx->rir->nWidth + 4 - LOGOINTERSECT, GContext::gType::HORIZONTAL }
			};
			for (uint8 i = 0; i < sizeof(points) / sizeof(*points); i++)
				if (*(dword*)&cord == *(dword*)&points[i].cord1) {
					if (ctx.call == points[i].call)
						return 0;
					if (i == 3)
						return L'+';

					GContext a = ctx;
					a.call = points[i].call;
					a.cord1 = points[i].cord1;
					a.p2 = points[i].p2;
					HANDLE hThread = CreateThread(nullptr, 0, (PTHREAD_START_ROUTINE)DrawLine, &a, NULL, nullptr);
					while (!a.bRead)
						Sleep(1);
					CloseHandle(hThread);
					return -1; // do Nothing
				}

			return 0;
		}
	}
}

namespace con {
#pragma region Console
	alignas(2) uint16 Console::m_nRefCounter = 0;
	           HANDLE Console::m_hConIn;
	           HANDLE Console::m_hConOut;
	           void*  Console::m_pBuffer;
	           size_t Console::m_nBuffer;

	Console::Console(
		_In_ dword pId
	) {
		if (!(_InterlockedIncrement16((short*)&m_nRefCounter) - 1)) {
			// Add additional logic for attaching to existing console
			if (!AttachConsole(pId))
				if (!AllocConsole())
					return;

#ifdef _DEBUG
			SetConsoleTitleW(L"[_riftldr] (debug/dev -build)");
#else
			SetConsoleTitleW(L"[_riftldr] (dev-build)");
#endif
			m_hConIn = GetStdHandle(STD_INPUT_HANDLE);
			m_hConOut = GetStdHandle(STD_OUTPUT_HANDLE);

			CONSOLE_SCREEN_BUFFER_INFO csbi;
			GetConsoleScreenBufferInfo(m_hConOut, &csbi);
			csbi.wAttributes &= 0xff00;
			csbi.wAttributes |= (word)Attributes::CON_INFO;
			SetConsoleTextAttribute(m_hConOut, csbi.wAttributes);
			Cls();

			m_pBuffer = VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}
	}
	Console::~Console() {
		if (!_InterlockedDecrement16((short*)&m_nRefCounter)) {
			// TODO: Add additional checks if programm was attached to existing console
			GetConsoleOriginalTitleW((wchar*)m_pBuffer, m_nBuffer);
			SetConsoleTitleW((wchar*)m_pBuffer);
			FreeConsole();
			VirtualFree(m_pBuffer, 0, MEM_RELEASE);
		}
	}

	status Console::Cls() {
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		status s = GetConsoleScreenBufferInfo(m_hConOut, &csbi);

		dword dw;
		s = FillConsoleOutputCharacterW(m_hConOut, L' ', csbi.dwSize.X * csbi.dwSize.Y, { 0, 0 }, &dw);
		s = !GetConsoleScreenBufferInfo(m_hConOut, &csbi);
		s = !FillConsoleOutputAttribute(m_hConOut, csbi.wAttributes, csbi.dwSize.X * csbi.dwSize.Y, { 0, 0 }, &dw);
		s = !SetConsoleCursorPosition(m_hConOut, { 0, 0 });

		return s;
	}
	status Console::WaitForSingleInput() {
		// Switch to raw mode
		DWORD dw;
		GetConsoleMode(m_hConIn, &dw);
		SetConsoleMode(m_hConIn, NULL);

		// Wait for the user's response
		WaitForSingleObject(m_hConIn, INFINITE);
		FlushConsoleInputBuffer(m_hConIn);

		// Restore the console to its previous state
		SetConsoleMode(m_hConIn, dw);
		return 0;
	}
	status Console::WriteW(
		_In_ word   wAttribute
	) {
		if (wAttribute & 0xf)
			SetConsoleTextAttribute(m_hConOut, wAttribute & 0xf);
		// WriteConsoleW(m_hConOut, m_pBuffer, nBufLen, (dword*)&nBufLen, NULL);
		return -1;
	}
	status Console::PrintFW(
		_In_     PCWSTR     pText,
		_In_     Attributes wAttribute,
		_In_opt_            ...
	) {
		va_list vaArg;
		va_start(vaArg, wAttribute);

		vswprintf_s((wchar*)m_pBuffer, 0x1000, pText, vaArg);
		m_nBuffer = wcslen((wchar*)m_pBuffer);

		va_end(vaArg);
		return m_nBuffer;
	}
#pragma endregion

#pragma region ConsoleGui
	void ConsoleGui::PrintIntro() {
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
			memset(&sr, 0, sizeof(SHORT) * 2);
			sr.Right = (riftLogo.nWidth + riftInfo.nWidth + 4) - LOGOINTERSECT;
			sr.Bottom = CUIHEIGHT - 1;

			// Set Console Window Size
			if (sr.Right <= csbi.srWindow.Right) {
				SetConsoleWindowInfo(m_hConOut, true, &sr);
				SetConsoleScreenBufferSize(m_hConOut, { sr.Right + 1, sr.Bottom + 1 });
				SetConsoleWindowInfo(m_hConOut, true, &sr);
			}
			else if (sr.Right > csbi.srWindow.Right) {
				SetConsoleScreenBufferSize(m_hConOut, { sr.Right + 1, sr.Bottom + 1 });
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
		a.p2 = CUIHEIGHT;
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
#pragma endregion
}

BOOL IOpenConsole() {
	con::ConsoleGui con;

	// con->PrintFW(L"Test", Console::Attributes::CON_ERROR);
	// con->PrintFW(L"Test, default");
	con.Cls();
	con.PrintIntro();

	return 0;
}