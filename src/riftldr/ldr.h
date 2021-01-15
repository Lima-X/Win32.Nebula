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
	#undef SearchPath
	status GetSystemDllbyHash(_In_ wchar* SearchPath, _In_ u64 Hash, _Out_ wchar* Path);
	void*  ImportFunctionByHash(_In_ handle Module, _In_ u64 Hash);
	handle GetModuleHandleByHash(_In_ u64 Hash);
	status ApplyBaseRelocationsOnSection(_In_ handle Module, _In_ IMAGE_SECTION_HEADER* Section, _In_opt_ void* Address, _In_ i64 RelocationDelta);
}

namespace svc {
	poly ServiceCall(_In_range_(0, 0xffff) u32 svcId, _In_opt_ ...);
	poly ServiceDispatch(_In_range_(0, 0xffff) u32 svcId, _In_opt_ va_list val);
}

namespace utl {
	void* CryptPointer(_In_ void* Pointer);

}

class svc2 {
	typedef poly(__x64call* ServiceFunctionPointer)(va_list VariableArgumentList);
	struct FunctionDispatchEntry {
		handle                 ModuleAssociation;
		u64                    FunctionId;
		ServiceFunctionPointer FunctionPointer;
	};

public:
	svc2();
	~svc2();

	status RegisterServiceFunction(_In_ u64 FunctionId, _In_ ServiceFunctionPointer FunctionPointer);
	status vServiceCall(_In_ u64 ServiceId, _Out_ poly* ReturnValue, _In_ va_list ServiceParameters);

private:
	status SearchListForEntry(
		_In_  u64 ServiceId,
		_Out_ FunctionDispatchEntry*& FunctionEntry
	);

	handle m_Heap;
};
inline svc2* ServiceMgr;

// Global Managment Information
struct {
	struct {
		u64 ProcessCookie;
		u64 HardwareId;
		u64 SessionId;
	} Process;
	handle ModuleBase;
} inline g_;
