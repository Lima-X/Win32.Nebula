#include "riftstb.h"

namespace svc { // Service Center/Dispatch Level:1 (svcdsp1)
	typedef long(__fastcall* svcdsp_t)(_In_range_(0, 0x7fff) uint16 svcId, _In_opt_ va_list val);
	static const svcdsp_t svcDispatch0;

	long svcDispatch1(
		_In_range_(0x1000, 0x1fff) uint16  svcId,
		_In_opt_                   va_list val
	) {
	#define v(T) va_arg(val, T)
	#define SDT_ENTRY(id, expr) case ((1 << 12) | id & 0x0fff):\
								s = (long)expr;\
								break
		long s;
		switch (svcId) {


			SDT_ENTRY(0xfff, 'svc1'); // TestEntry, a call to svc with id 0xfff should return 'svc##N'
		default:
			s = -1; // Invalid Id, abort
		}
	#undef v

		return s;
	}

	long svcCall(
		_In_range_(0, 0x1fff) uint16 svcId,
		_In_opt_                     ...
	) {
		va_list val;
		va_start(val, svcId);

		long s;
		if (svcId >= 0x1000)              // Check if Service-Call is ours
			s = svcDispatch1(svcId, val); // Call a Stub Service (Current)
		else
			s = svcDispatch0(svcId, val); // Call a Loader Service

		va_end(val);
		return s;
	}
}

status WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ dword     fdwReason,
	_In_ void*     pvReserved
) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;

	case 4: // Transmit Service Center
		const_cast<svc::svcdsp_t&>(svc::svcDispatch0) = (svc::svcdsp_t)pvReserved;
	case 5:

	case 6: // System Shutdown
		;
	}

	return true;
}
