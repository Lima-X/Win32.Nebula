// LoaderModule
#pragma once

#include "core.h"

#pragma region Protected Sections
#pragma warning(disable : 4330)
// Protected sections
#pragma section(".nbr", read)  // Constsection
#pragma section(".nbw", write) // Datasection

// Merge protected sections
#pragma comment(linker, "/merge:.nbr=.nb0")
#pragma comment(linker, "/merge:.nbw=.nb0")
#pragma comment(linker, "/merge:.nbx=.nb0")
// Merge loader code into a loader section
#pragma comment(linker, "/merge:.text=.ldr")
// #pragma comment(linker, "/merge:.data=.ldr")
#pragma comment(linker, "/merge:.rdata=.ldr")

// Declaration Protection Specification
#define N_PROTECTEDR ALLOC_DATA(".nbr")
#define N_PROTECTEDW ALLOC_DATA(".nbw")
#define N_PROTECTEDX ALLOC_CODE(".nbx")
#pragma endregion

namespace ldr {
	LIST_ENTRY* GetModuleList();
	#undef SearchPath
	status GetSystemDllbyHash(_In_ wchar* SearchPath, _In_ u64 Hash, _Out_ wchar* Path);
	void*  ImportFunctionByHash(_In_ handle Module, _In_ u64 Hash);
	handle GetModuleHandleByHash(_In_ u64 Hash);
	status ApplyBaseRelocationsOnSection(_In_ handle Module, _In_ IMAGE_SECTION_HEADER* Section, _In_opt_ void* Address, _In_ i64 RelocationDelta);
}

status ValidateImportAddressTable(_In_ handle Module);

namespace svc {
	poly ServiceCall(_In_range_(0, 0xffff) u32 svcId, _In_opt_ ...);
	poly ServiceDispatch(_In_range_(0, 0xffff) u32 svcId, _In_opt_ va_list val);
}

namespace utl {
	void* CodePointer(_In_ void* Pointer);
	poly CryptPointer2(_In_ poly x);

}

class svc2 {
	typedef poly(__x64call* ServiceFunctionPointer)(poly VariableArgumentList);
	struct FunctionDispatchEntry {
		handle                 ModuleAssociation;
		u64                    FunctionId;
		ServiceFunctionPointer FunctionPointer;
	};

public:
	 svc2();
	~svc2();

	status RegisterServiceFunction(_In_ u64 FunctionId, _In_ ServiceFunctionPointer FunctionPointer);
	status ServiceCall(_In_ u64 ServiceId, _Out_ poly* ReturnValue, _In_opt_ poly ServiceParameters);

private:
	status SearchListForEntry(_In_ u64 ServiceId, _Out_ FunctionDispatchEntry*& FunctionEntry);

	handle m_DispatchTable; // Function-Dispatch-Table (HeapList storing the Services)
};
inline svc2* ServiceMgr;

// Global Managment Information
// has to be named because of a stupid compiler bug lol, bug report at:
// https://developercommunity.visualstudio.com/content/problem/1312147/c17-global-unnamed-inline-struct-may-not-be-the-sa.html
struct _NebulaInternalGlobalData {
	handle ModuleBase;

	u64 ProcessCookie;
	u8  CookieOffset;

	u64 HardwareId;
	u64 SessionId;
} volatile inline g_;
