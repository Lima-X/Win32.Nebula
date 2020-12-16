// Nebula-SDK/API Header declaring everything needed for
#pragma once

// if SAL is unavailable define them to resolve to nothing
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _In_range_
#define _In_range_()
#endif
#ifndef _Success_()
#define _Success_()
#endif

#include <stdarg.h>
#include "sub/def.h"
#include "sub/status.h"

#ifdef __cplusplus
namespace svc {
	typedef poly(*ServiceCall_t)(
		_In_range_(0, 0xffff) u32 svcId,
		_In_opt_                  ...
		);
	typedef poly(*vServiceCall_t)(
		_In_range_(0, 0xffff) u32     svcId,
		_In_opt_              va_list val
		);

	   inline  ServiceCall_t  ServiceCall;
	// inline vServiceCall_t vServiceCall;
}
#else
typedef poly(*NbServiceCall_t)(
	_In_range_(0, 0xffff) u32 svcId,
	_In_opt_                  ...
	);
typedef poly(*NbvServiceCall_t)(
	_In_range_(0, 0xffff) u32     svcId,
	_In_opt_              va_list val
	);
   extern  NbServiceCall_t  NbServiceCall;
// extern NbvServiceCall_t NbvServiceCall;
#endif