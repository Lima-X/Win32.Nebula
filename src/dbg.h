/* Debug Library: Defines debugging related code used to debug, trace/log and test code,
                  all contianed within one header as a almost standalone library,
				  that is mutually excluded in non debug builds. */
#pragma once
#pragma comment(lib, "ntdllp.lib")
#include <windows.h>
#pragma comment(lib, "dbghelp.lib")
#include <dbghelp.h>

#ifdef __cplusplus
extern "C" {
#endif
	__declspec(dllimport) ULONG __stdcall vDbgPrintEx(_In_ ULONG ComponentId, _In_ ULONG Level, _In_z_ PCCH Format, _In_ va_list arglist);
	__declspec(dllimport) int __cdecl swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...);
	__declspec(dllimport) int __cdecl vsprintf_s(char* buffer, size_t numberOfElements, const char* format, va_list argptr);
#ifdef __cplusplus
}
#endif

inline long DbgCreateDump(                             // Generates a MiniDumpFile of the current process
	_In_opt_z_ const wchar_t*            Path,         // The path at which to create the dumpfile and write to
	_In_opt_         EXCEPTION_POINTERS* ExceptionInfo // Optional exceptionpointers incase an exception occoured
) {
	auto Heap = GetProcessHeap();
	auto ModuleFile = (wchar_t*)HeapAlloc(Heap, 0, MAX_PATH);
	if (!ModuleFile)
		return -1;

	// Search for Basename
	GetModuleFileNameW(GetModuleHandleW(nullptr), ModuleFile, MAX_PATH);
	size_t StringLength = wcslen(ModuleFile);
	auto BaseName = ModuleFile + StringLength;
	while (*--BaseName != L'\\');

	// Create Dumpfile
	auto TargetFile = (wchar_t*)HeapAlloc(Heap, 0, MAX_PATH);
	auto AppandingOffset = 0;
	if (Path) {
		wcscpy(TargetFile, Path);
		AppandingOffset = wcslen(Path);
		TargetFile[AppandingOffset++] = L'\\';
	}
	swprintf_s(TargetFile + AppandingOffset, MAX_PATH, L"%s%04d_%#018llx.dmp", ++BaseName, GetCurrentProcessId(), __rdtsc());
	HeapFree(Heap, 0, ModuleFile);
	handle hFile = CreateFileW(TargetFile, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, CREATE_ALWAYS, NULL, NULL);
	HeapFree(Heap, 0, TargetFile);
	if (hFile == INVALID_HANDLE_VALUE)
		return -2;

	// Create and Write Minidump
	MINIDUMP_EXCEPTION_INFORMATION mdei;
	mdei.ExceptionPointers = ExceptionInfo;
	mdei.ThreadId = GetCurrentThreadId();
	mdei.ClientPointers = false;
	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
		hFile, MiniDumpNormal, &mdei, nullptr, nullptr);

	CloseHandle(hFile);
	return 0;
}

#ifdef _DEBUG
#define DBG_ERROR   0 //
#define DBG_WARNING 1 //
#define DBG_SUCCESS 2 //
#define DBG_MESSAGE 3 //
inline void DbgTracePoint(
	_In_opt_ u32         ErrorLevel,
	_In_z_   const char* FormatString,
	_In_opt_             ...
) {
	auto Buffer = (char*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	auto Iterator = Buffer;

	// Print errorlevel symbol
	*Iterator++ = '[';
	switch (ErrorLevel) {
	case DBG_ERROR:   *Iterator++ = 'X'; break;
	case DBG_WARNING: *Iterator++ = '!'; break;
	case DBG_SUCCESS: *Iterator++ = 'S'; break;
	case DBG_MESSAGE: *Iterator++ = '+';
	}
	*Iterator++ = ']'; *Iterator++ = ' ';

	// Generate alligned Buffer
	while (*FormatString) {
		*Iterator++ = *FormatString;
		if (*FormatString++ == '\n') {
			for (auto i = 0; i < 4; i++)
				*Iterator++ = ' ';
		};
	}
	*Iterator = '\n'; // Auto Newline

	// Print Message
	va_list Arguments;
	va_start(Arguments, FormatString);
	vDbgPrintEx(0x65, ErrorLevel, Buffer, Arguments);
	va_end(Arguments);

	VirtualFree(Buffer, 0, MEM_RELEASE);
}
#endif

#if defined(_DEBUG) && defined(__cplusplus)
// will be renamed to dbg when the original old code has been fully regfactored modified
// Old Code, will be fixed up, refactored, moved to dbg2 or removed
namespace dbg {
#pragma region Intermediate/Developmental Debugging
	class DbgBenchmark {
	public:
		typedef void nul;
		enum class Resolution : u32 {
			SEC = 1,
			MILLI = 1000,
			MICRO = 1000000,
			NANO = 1000000000
		};

		DbgBenchmark(
			_In_ Resolution res = Resolution::MILLI
		)
		#ifdef _DEBUG
			: m_res(res) {
			if (!m_liFrequenzy.QuadPart)
				QueryPerformanceFrequency(&m_liFrequenzy);
		#else
			{
		#endif
			}

		void Begin() {
		#ifdef _DEBUG
			QueryPerformanceCounter(&m_liBegin);
		#endif
		}
		u64 End() {
		#ifdef _DEBUG
			QueryPerformanceCounter(&m_liEnd);

			// Calculate time difference, whole and part
			m_liEnd.QuadPart -= m_liBegin.QuadPart;
			u64 Whole = (m_liEnd.QuadPart / m_liFrequenzy.QuadPart) * (u64)m_res;
			u64 Part = (m_liEnd.QuadPart % m_liFrequenzy.QuadPart) * (u64)m_res;
			Part /= m_liFrequenzy.QuadPart;

			return Whole + Part;
		#endif
		}

	private:
	#ifdef _DEBUG
		static LARGE_INTEGER m_liFrequenzy;
		const  Resolution    m_res;
		       LARGE_INTEGER m_liBegin;
		       LARGE_INTEGER m_liEnd;
	#endif
		};
	inline LARGE_INTEGER DbgBenchmark::m_liFrequenzy;

	class DbgLog {
	public:
		static DbgLog& Instance() {
			static DbgLog instance;
			return instance;
		}

		void Trace(
			_In_     const char* sz,
			_In_opt_             ...
		) {
			__try {
				char* psz = (char*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				if (!psz)
					return;

				size_t nLen;
				// Format if needed
					va_list va;
					va_start(va, sz);
					vsprintf_s(psz, 0x1000, sz, va);
					va_end(va);
					nLen = strlen(psz);

				if (psz[nLen] != '\n')
					*(word*)&psz[nLen] = '\0\n';
				WriteToLog(psz, nLen + 1);
				VirtualFree((void*)psz, NULL, MEM_RELEASE);
			} __except (RecursiveException(GetExceptionInformation())) {}
		}

	private:
		DbgLog() {
			m_hFile = CreateFileW(L"rift.log", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
				nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			PTOP_LEVEL_EXCEPTION_FILTER uef = [](EXCEPTION_POINTERS* ctx) -> long {
				auto log = Instance();
				log.Trace("Unhandled Exception caught! @: %#018x, Exception:%#018x",
					ctx->ExceptionRecord->ExceptionAddress, ctx->ExceptionRecord->ExceptionCode);
				CloseHandle(log.m_hFile);

				return EXCEPTION_CONTINUE_SEARCH;
			};
			SetUnhandledExceptionFilter(uef);

			PVECTORED_EXCEPTION_HANDLER veh = [](EXCEPTION_POINTERS* ctx) -> long {
				Instance().Trace("Exception occurred! @: %#018x, Exception:%#018x\nTrying to resume Execution.",
					ctx->ExceptionRecord->ExceptionAddress, ctx->ExceptionRecord->ExceptionCode);

				return EXCEPTION_CONTINUE_SEARCH;
			};
			AddVectoredExceptionHandler(NULL, veh);
		}
		~DbgLog() {
			CloseHandle(m_hFile);
		}

		static status WriteToLog(
			_In_ handle h,
			_In_ void* pBuf,
			_In_ size_t nBuf
		) {
			dword dw;
			if (WriteFile(h, pBuf, nBuf, &dw, nullptr))
				return dw;
			return -1;
		}
		status WriteToLog(
			_In_ void* pBuf,
			_In_ size_t nBuf
		) {
			return WriteToLog(m_hFile, pBuf, nBuf);
		}

		static long RecursiveException(EXCEPTION_POINTERS* ctx) {
			handle hFile = DbgLog::Instance().m_hFile;
			WriteToLog(hFile, (char*)"\nRecursive Exception occurred!\n"
				"Can't continue search/execution, aborting Process", 80);
			CloseHandle(hFile);
			__fastfail(ctx->ExceptionRecord->ExceptionCode);
			return 0; // doesn't matter as we fastfail before anyways, but is needed to make the compiler happy.
		}


		handle m_hFile;
	};
#pragma endregion


#pragma region Utility Debugging
	// Temporery DllInjector, this allows for JIT debugging which manualmapping can't really do
	inline status InjectDllW(
		_In_z_ const wchar* szDll,
		_In_         dword  dwPid
	) {
		handle hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (!hProc)
			return -1; // Failed to open target Process

		void* rpDllPath = VirtualAllocEx(hProc, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!rpDllPath)
			return -2; // Failed to allocate remote Memory
		if (!WriteProcessMemory(hProc, rpDllPath, szDll, wcslen(szDll), NULL))
			return -3; // Failed to write to remote Memory

		void* pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
		if (!pLoadLibraryW)
			return -4; // Failed to get Loaderfunctionaddress
		handle hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, rpDllPath, NULL, NULL);
		if (!hRemoteThread)
			return -5; // Failed to create remote Thread

		WaitForSingleObject(hRemoteThread, INFINITE);
		dword dwRemote;
		GetExitCodeThread(hRemoteThread, &dwRemote);

		CloseHandle(hRemoteThread);
		VirtualFreeEx(hProc, rpDllPath, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return dwRemote;
	}
#pragma endregion
}
#endif

#define BreakPoint   __debugbreak
#define CreateDump   DbgCreateDump
#ifdef _DEBUG
#define TracePoint   DbgTracePoint
#else
#define TracePoint()
#endif
