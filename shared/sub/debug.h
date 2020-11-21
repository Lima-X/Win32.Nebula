// This Defines Debugging related code used to Debug, Trace/Log and Test Code
#pragma once
#ifdef __cplusplus
#include <cstdio>

namespace dbg {
#pragma region Debugging
	/* Because of how the C Preprocessor works (Macro's)
	   Im forced to either rely on:
	   - WPO and LTO optimizations (which I would actually trust ~~but dont want to~~ (actually using them now))
	   - Use some weird as fucker to reform the expression into something else that is valid but goes into nothing
	   - Use plain C to write my "Debugging API" which will be ugly and wont fit the C++ style im aiming for */

#ifdef _DEBUG

	inline bool CheckIfFormatRequired(
		_In_z_ const char* sz
	) {
		for (uint16 i = 0; sz[i] != NULL; i++) {
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
	inline void dbgTracePoint(
		_In_z_   const char* sz,
		_In_opt_             ...
	) {
		bool b = CheckIfFormatRequired(sz);

		char* psz = (char*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!psz)
			return;

		size_t nLen = strlen(sz);
		// Format if needed
		if (b) {
			va_list va;
			va_start(va, sz);
			vsprintf_s(psz, 0x1000, sz, va);
			va_end(va);
		} else
			memcpy(psz, sz, nLen + 1);
		if (psz[nLen - 1] != '\n')
			*(word*)&psz[nLen] = '\0\n';

		OutputDebugStringA(psz);
		VirtualFree((void*)psz, NULL, MEM_RELEASE);
	}

	inline void dbgStatusAssert(
		_In_           status s,
		_In_     const char* sz,
		_In_opt_       ...
	) {
		if (s < 0) {
			dbgTracePoint(sz, s);
			RaiseException(s, EXCEPTION_NONCONTINUABLE, NULL, NULL);
		}
	}
#pragma endregion

#pragma region Intermediate/Developmental Debugging
	class Benchmark {
	public:
		typedef void nul;
		enum class Resolution : uint32 {
			SEC = 1,
			MILLI = 1000,
			MICRO = 1000000,
			NANO = 1000000000
		};

		Benchmark(
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
		uint64 End() {
		#ifdef _DEBUG
			QueryPerformanceCounter(&m_liEnd);

			// Calculate time difference, whole and part
			m_liEnd.QuadPart -= m_liBegin.QuadPart;
			uint64 Whole = (m_liEnd.QuadPart / m_liFrequenzy.QuadPart) * (uint64)m_res;
			uint64 Part = (m_liEnd.QuadPart % m_liFrequenzy.QuadPart) * (uint64)m_res;
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
	inline LARGE_INTEGER Benchmark::m_liFrequenzy;

	class Log {
	public:
		static Log& Instance() {
			static Log instance;
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
		Log() {
			m_hFile = CreateFileW(L"rift.log", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
				nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			PTOP_LEVEL_EXCEPTION_FILTER uef = [](EXCEPTION_POINTERS* ctx) -> long {
				Log log = Instance();
				log.Trace("Unhandled Exception caught! @: %#010x, Exception:%#010x",
					ctx->ExceptionRecord->ExceptionAddress, ctx->ExceptionRecord->ExceptionCode);
				CloseHandle(log.m_hFile);

				return EXCEPTION_CONTINUE_SEARCH;
			};
			SetUnhandledExceptionFilter(uef);

			PVECTORED_EXCEPTION_HANDLER veh = [](EXCEPTION_POINTERS* ctx) -> long {
				Instance().Trace("Exception occurred! @: %#010x, Exception:%#010x\nTrying to resume Execution.",
					ctx->ExceptionRecord->ExceptionAddress, ctx->ExceptionRecord->ExceptionCode);

				return EXCEPTION_CONTINUE_SEARCH;
			};
			AddVectoredExceptionHandler(NULL, veh);
		}
		~Log() {
			CloseHandle(m_hFile);
		}

		static status WriteToLog(
			_In_ HANDLE h,
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
			HANDLE hFile = Log::Instance().m_hFile;
			WriteToLog(hFile, (char*)"\nRecursive Exception occurred!\n"
				"Can't continue search/execution, aborting Process", 80);
			CloseHandle(hFile);
			__fastfail(ctx->ExceptionRecord->ExceptionCode);
			return 0; // doesn't matter as we fastfail before anyways, but is needed to make the compiler happy.
		}


		HANDLE m_hFile;
	};
#pragma endregion


#pragma region Utility Debugging
	// Temporery DllInjector, this allows for JIT debugging which manualmapping can't really do
	inline status InjectDllW(
		_In_z_ const wchar* szDll,
		_In_         dword  dwPid
	) {
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
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
		HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, rpDllPath, NULL, NULL);
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
#endif
}
#endif

#define BreakPoint __debugbreak
#ifdef _DEBUG
#define TracePoint ::dbg::dbgTracePoint
#define StatusAssert ::dbg::dbgStatusAssert
#else
#define TracePoint()
#define StatusAssert()
#endif
