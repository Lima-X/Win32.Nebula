#include "ldr.h"

namespace svc { // Service Center/Dispatch Level:0 (svcdsp0)
	// Creates a Entry for a Service in the Servicedispatchtable (svcdspt)
	// In order to use a void function prepend "0;" to the expr
	#define SDT_ENTRY(Id, expr) case ((0 << 12) | Id & 0xffff):\
								Ret = (poly)expr;\
								break
	#define v(T) va_arg(val, T)
	poly ServiceDispatch(
		_In_range_(0, 0xffff) u32     svcId,
		_In_opt_              va_list val
	) {
		poly Ret;
		switch (svcId) {


			SDT_ENTRY(0xffff, ServiceDispatch); //
		default:
			Ret = (poly)-1; // Invalid Id, abort
		}

		return Ret;
	}
	#undef v

	poly ServiceCall(
		_In_range_(0, 0xffff) u32 svcId,
		_In_opt_                  ...
	) {
		va_list val;
		va_start(val, svcId);

		poly Ret = ServiceDispatch(svcId, val);

		va_end(val);
		return Ret;
	}
}
