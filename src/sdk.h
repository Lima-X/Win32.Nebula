/* Nebula-SDK/API Header provides all Names and Declarations required
   in order to code Plugins/Extensions and Payloads */
#pragma once

#ifndef _NB_SDK   // This block automatically activates the SDK
#define _NB_SDK 1 // enabling certain features and providing delcarations
#endif            // ()

#ifdef _NB_SDK_PROVIDE_DEBUG
#include "dbg.h"
#endif
#include "base.h"

#if _NB_SDK
typedef poly(__x64call*vServiceCall_t)(
	_In_range_(0, 0xffff) u32     svcId,
	_In_opt_              va_list val
	);
inline vServiceCall_t vServiceCall;

/* Example: Call a servicefunction and pass 2 parameters
	poly ParameterList[2];
	ParameterList[0] = "String Part 1";
	ParameterList[1] = 0x1234;
	poly ReturnValue;
	status StatusCode = vServiceCall(SERVICE_ID, &ReturnValue, (poly)ParameterList);
*/
#endif

typedef void(__x64call* tapc_t)(
	_In_opt_ poly UserContext // Callback defined Context
	);


#pragma region ModuleEntry
#define N_ONLOAD    1
#define N_RUNMOD    2
#define N_UNLOAD    3
#define N_FATAL     4
#define N_VIOLATION	5

#pragma endregion
