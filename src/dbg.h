/* Debug Library: Defines debugging related code used to debug, trace/log and test code,
                  all contianed within one header as a almost standalone library,
				  that is mutually excluded in non debug builds. */
#pragma once
#define _DEBUG

#if defined(_DEBUG) && defined(__cplusplus)
#pragma comment(lib, "ntdllp.lib")
#include <windows.h>
#pragma comment(lib, "dbghelp.lib")
#include <dbghelp.h>

__declspec(dllimport) ULONG __cdecl vDbgPrint(_In_z_ _Printf_format_string_ PCSTR Format, ...);
__declspec(dllimport) int __cdecl swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...);

// will be renamed to dbg when the original old code has been fully regfactored modified
namespace dbg2 {
	inline status CreateDump(                                   // Generates a MiniDumpFile of the current process
		_In_z_   const wchar*              Path,         // The path at which to create the dumpfile and write to
		_In_opt_       EXCEPTION_POINTERS* ExceptionInfo // Optional exceptionpointers incase an exception occoured
	) {
		auto Heap = GetProcessHeap();
		auto Temporary1 = (wchar*)HeapAlloc(Heap, 0, MAX_PATH);

		// Search for Basename
		GetModuleFileNameW(GetModuleHandleW(nullptr), Temporary1, MAX_PATH);
		size_t StringLength = wcslen(Temporary1);
		auto BaseName = Temporary1 + StringLength;
		while (*--BaseName != L'\\');

		// Create Dumpfile
		auto Temporary2 = (wchar*)HeapAlloc(Heap, 0, MAX_PATH);
		swprintf_s(Temporary2, MAX_PATH, L"\\%s%04d_%#018llx.dmp", ++BaseName, GetCurrentProcessId(), __rdtsc());
		auto MiniDumpFileName = Temporary1;
		wcscpy(MiniDumpFileName, Path);
		wcscat(MiniDumpFileName, Temporary2);
		HeapFree(Heap, 0, Temporary2);
		handle hFile = CreateFileW(MiniDumpFileName, GENERIC_READWRITE,
			FILE_SHARE_READ, nullptr, CREATE_ALWAYS, NULL, NULL);
		HeapFree(Heap, 0, MiniDumpFileName);
		if (hFile == INVALID_HANDLE_VALUE)
			return S_CREATE(SS_ERROR, SF_NULL, SC_INVALID_HANDLE);

		// Create and Write Minidump
		MINIDUMP_EXCEPTION_INFORMATION mdei;
		mdei.ExceptionPointers = ExceptionInfo;
		mdei.ThreadId = GetCurrentThreadId();
		mdei.ClientPointers = false;
		MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
			hFile, MiniDumpNormal, &mdei, nullptr, nullptr);

		CloseHandle(hFile);
		return SUCCESS;
	}
}

// Old Code, will be fixed up, refactored, moved to dbg2 or removed
namespace dbg {
	DEPRECATED inline bool CheckIfFormatRequired(
		_In_z_ const char* sz
	) {
		for (u16 i = 0; sz[i] != NULL; i++) {
			if (sz[i] == '%')
				if (sz[i + 1] != '%') {
					return true;
				} else
					i++;
		}

		return false;
	}

#pragma region Direct Debugging (through Debugger)
	// This is fucked but works for whatever reason
	DEPRECATED inline void DbgTracePoint(
		_In_z_   const char* String,
		_In_opt_             ...
	) {
		bool b = CheckIfFormatRequired(String);

		char* psz = (char*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!psz)
			return;

		size_t nLen = strlen(String);
		// Format if needed
		if (b) {
			va_list va;
			va_start(va, String);
			vsprintf_s(psz, 0x1000, String, va);
			va_end(va);
		} else
			memcpy(psz, String, nLen + 1);
		if (psz[nLen - 1] != '\n')
			*(word*)&psz[nLen] = '\0\n';

		OutputDebugStringA(psz);
		VirtualFree((void*)psz, NULL, MEM_RELEASE);
	}

	DEPRECATED inline void DbgStatusAssert(
		_In_           status Status,
		_In_z_   const char*  String,
		_In_opt_              ...
	) {
		if (S_ISSUE(Status)) {
			DbgTracePoint(String, Status);
			RaiseException(Status, EXCEPTION_NONCONTINUABLE, NULL, NULL);
		}
	}
#pragma endregion

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
				bool b = CheckIfFormatRequired(sz);

				char* psz = (char*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				if (!psz)
					return;

				size_t nLen;
				// Format if needed
				if (b) {
					va_list va;
					va_start(va, sz);
					vsprintf_s(psz, 0x1000, sz, va);
					va_end(va);
					nLen = strlen(psz);
				} else {
					nLen = strlen(sz);
					memcpy(psz, sz, nLen + 1);
				}

				if (psz[nLen] != '\n')
					*(word*)&psz[nLen] = '\0\n';
				WriteToLog(psz, nLen + 1);
				VirtualFree((void*)psz, NULL, MEM_RELEASE);
			} __except (RecursiveException(GetExceptionInformation())) {}
		}
		void Trace(
			_In_ void* pBuf,
			_In_ size_t nBuf
		) {

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
#ifdef _DEBUG
#define CreateDump   ::dbg2::CreateDump
#define TracePoint   ::dbg::dbgTracePoint
#define StatusAssert ::dbg::dbgStatusAssert
#else
#define CreateDump()
#define TracePoint()
#define StatusAssert()
#endif