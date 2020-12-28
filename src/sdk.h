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

#ifdef _M_X64
#define __x64call
#else
#define __x64call INVALID_CALLING_CONVENTION // This cause a compiler error
#endif

#ifdef __cplusplus
namespace svc {
	typedef poly(__x64call*ServiceCall_t)(
		_In_range_(0, 0xffff) u32 svcId,
		_In_opt_                  ...
		);
	typedef poly(__x64call*vServiceCall_t)(
		_In_range_(0, 0xffff) u32     svcId,
		_In_opt_              va_list val
		);

	   inline  ServiceCall_t  ServiceCall;
	// inline vServiceCall_t vServiceCall;
}
#else
typedef poly(__x64call*NbServiceCall_t)(
	_In_range_(0, 0xffff) u32 svcId,
	_In_opt_                  ...
	);
typedef poly(__x64call*vNbServiceCall_t)(
	_In_range_(0, 0xffff) u32     svcId,
	_In_opt_              va_list val
	);
   extern  NbServiceCall_t  NbServiceCall;
// extern vNbServiceCall_t vNbServiceCall;
#endif