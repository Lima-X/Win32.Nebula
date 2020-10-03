#include "global.h"

namespace nid {
	// Dummy for hash datatype (Md5 class will be moved here in the future)
	namespace cry { class Md5 { public: typedef GUID hash; }; }

	void WrapHash(
		_Inout_ cry::Md5::hash hToWrap,
		_In_    cry::Md5::hash hWrap
	) {
		for (uint8 i = 0; i < sizeof(hToWrap); i++)
			(*(byte**)&hToWrap)[i] ^= (*(byte**)&hWrap)[i];
	}
}

// This contains utilities for debugging (only implemented in Debug config)
#include <cstdio>
namespace dbg {
#ifdef _DEBUG
	LARGE_INTEGER Benchmark::m_liFrequenzy;
#endif
	Benchmark::Benchmark(
		_In_ resolution res
	)
#ifdef _DEBUG
		: m_res(res)
#endif
	{
#ifdef _DEBUG
		if (!m_liFrequenzy.QuadPart)
			QueryPerformanceFrequency(&m_liFrequenzy);
#endif
	}

	void Benchmark::Begin() {
#ifdef _DEBUG
		QueryPerformanceCounter(&m_liBegin);
#endif
	}
	// (yes this uses the 64bit integers on 32bit arch (its ok for debugging))
	uint64 Benchmark::End() {
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

	void TracePoint(
		_In_     const char* sz,
		_In_opt_             ...
	) noexcept {
#ifdef _DEBUG
		// Check if Formating is required
		bool b = false;
		for (uint16 i = 0; sz[i] != NULL; i++) {
			if (sz[i] == '%')
				if (sz[i + 1] != '%')
					i++;
				else
					b = true;
		}

		// Format if needed
		if (b) {
			va_list va;
			va_start(va, sz);
			char* psz = (char*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if (!psz)
				return;
			vsprintf_s(psz, 0x1000, sz, va);
			va_end(va);
			sz = psz;
		}
		OutputDebugStringA(sz);
		if (b)
			VirtualFree((void*)sz, NULL, MEM_RELEASE);
#endif
	}

	void StatusAssert(
		_In_           status s,
		_In_     const char* sz,
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
		dword dwRemote;
		GetExitCodeThread(hRemoteThread, &dwRemote);

		CloseHandle(hRemoteThread);
		VirtualFreeEx(hProc, rpDllPath, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return dwRemote;
#endif
	}
}
