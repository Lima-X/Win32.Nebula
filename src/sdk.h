/* Nebula-SDK/API Header provides all Names and Declarations required
   in order to code Plugins/Extensions and Payloads */
#pragma once

/* This block automatically activates the SDK
   enabling certain features and providing delcarations
   (do not manually disable the sdk for client code,
   this feature is reserved for internal use) */
#ifndef _NB_SDK
#define _NB_SDK 1
#endif

// Enable SDK debug features (optional)
#ifdef _NB_SDK_PROVIDE_DEBUG
#include "dbg.h"
#endif
#include "base.h"

#define N_PSR ".nbr" // Protected Sections (Read/Write/Execute rwx)
#define	N_PSW ".nbw"
#define N_PS0 ".nb0" // Core protected code and data (packed and encrypted)
                     // will be decrypted and unpacked during TLS
#define N_PS1 ".nb1" // Intermediate protected code (encrypted)
                     // functions that should be unreadable for most of the time,
                     // the section would be decrypted for a call and reencrypted again.

#if _NB_SDK
/* Example: Call a servicefunction and pass 2 parameters
	poly ParameterList[2];
	ParameterList[0] = "String Part 1";
	ParameterList[1] = 0x1234;
	poly ReturnValue;
	status StatusCode = vServiceCall(SERVICE_ID, &ReturnValue, (poly)ParameterList);
*/
#endif

// ThreadInterruptService
typedef void(__x64call* tapc_t)(
	_In_opt_ poly UserContext // Callback defined Context
	);

#pragma region ModuleEntry
#define N_ONLOAD    1
#define N_RUNMOD    2
#define N_UNLOAD    3
#define N_FATAL     4
#define N_VIOLATION	5
#define N_DEFECT    6
#define N_SHUTDOWN  7

typedef status(__x64call* cec_t)(      // Client Entrypoint Callback (CEC)
	_In_        i32    CallReason,     // The reason for the call
	_Inout_opt_ void*  PointerTable[8] // Pointer table used to pass info to the core
	);
#pragma endregion

#undef _NB_SDK
