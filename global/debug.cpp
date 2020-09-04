#include "global.h"
#include <cstdio>

namespace dbg {
	class Benchmark {
	public:
		enum class resolution : uint32 {
			SEC = 1,
			MILLI = 1000,
			MICRO = 1000000,
			NANO = 1000000000
		};

		Benchmark(
			_In_ resolution res = resolution::MILLI
		)
#ifdef _DEBUG
			: m_res(res)
#endif
		{
#ifdef _DEBUG
			QueryPerformanceFrequency(&m_liFrequenzy);
#endif
		}

		inline void Begin() {
#ifdef _DEBUG
			QueryPerformanceCounter(&m_liBegin);
#endif
		}
		// (yes this uses the 64bit integers on 32bit arch (its ok for debugging))
		inline uint64 End() {
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
		LARGE_INTEGER m_liFrequenzy;
		const resolution m_res;
		LARGE_INTEGER m_liBegin;
		LARGE_INTEGER m_liEnd;
#endif
	};

	void TracePoint(
		_In_     const char* sz,
		_In_opt_       ...
	) noexcept {
#ifdef _DEBUG
		va_list va;
		va_start(va, sz);
		char* szf = (char*)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!szf)
			return;
		vsprintf_s(szf, 4096, sz, va);
		va_end(va);
		OutputDebugStringA(sz);
		VirtualFree(szf, NULL, MEM_RELEASE);
#endif
	}

	void StatusAssert(
		_In_           status s,
		_In_     const char*  sz,
		_In_opt_       ...
	) {
#ifdef _DEBUG
		if (s < 0) {
			TracePoint(sz, s);
			RaiseException(s, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
		}
#endif
	}

	// Temporery DllInjector, this allows for JIT debugging which manualmapping can't really do
	status InjectDllW(
		_In_ const wchar* szDll,
		_In_       dword  dwPid
	) {
#ifdef _DEBUG
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, dwPid);
		if (!hProc)
			return -1; // Failed to open target Process

		void* rpDllPath = VirtualAllocEx(hProc, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!rpDllPath)
			return -2; // Failed to allocate remote Memory
		if (!WriteProcessMemory(hProc, rpDllPath, szDll, wcslen(szDll), nullptr))
			return -3; // Failed to write to remote Memory

		void* pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
		if (!pLoadLibraryW)
			return -4; // Failed to get Loaderfunctionaddress
		HANDLE hRemoteThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, rpDllPath, NULL, nullptr);
		if (!hRemoteThread)
			return -5; // Failed to create remote Thread

		WaitForSingleObject(hRemoteThread, INFINITE);
		HANDLE hRemoteLib;
		GetExitCodeThread(hRemoteThread, (dword*)&hRemoteLib);

		CloseHandle(hRemoteThread);
		VirtualFreeEx(hProc, rpDllPath, 0, MEM_RELEASE);
		CloseHandle(hProc);

		return (status)hRemoteLib;
#endif
	}

}