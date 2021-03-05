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
#pragma comment(lib, "ntdllp.lib") // Link against ntdll (Full link through private lib)


#pragma region Nebula Protection SDK v1 (deprecated)
#define N_PSRW1 ".nbrw1" // Protected Sections (Read/Write rwx)
#define	N_PSRW2 ".nbrw2"

#define N_PS0   ".nb0" // Unprotected default section
                       // everything that is unspecified is put here
#define N_PS1   ".nb1" // Core protected code and data (packed and encrypted)
                       // will be decrypted and unpacked during TLS
#define N_PS2   ".nb2" // Intermediate protected code and data (encrypted)
                       // stuff that should be unreadable unless actively used,
#pragma endregion



#pragma region Nebula Protect SDKv2
#define NB_NBDS ".nb0" // Nebula's default section,
                      // everything that is not explicitly allocated is stored in here
                      // this includes code and data, both of which can be crypted.
                      // This section can NOT be compressed and is rwx protected.
#define NB_NBPS ".pk0" // Nebula's default compressed section,
                      // this is the default section for all data and code internaly used,
                      // that is not required to be present for initialization.
                      // Crypted code or data can also be stored here, however the compression
                      // will mostlikely proof itself ineffective.

#pragma section(".nbft", read) // NebulaProtectSeg - Everything in here is pure
                               // data and is used internaly by the core and builder.
                               // This can later just be merged into the main section,
                               // that is if its not stripped by the builder entirely.

#pragma region Nebula Crypto Table
#define NB_CRYPTFUNC    NOINLINE
#define NB_COMPRESSFUNC ALLOC_CODE(NB_NBPS)
#define NB_CRYPTDATA
#define NB_COMPRESSDATA ALLOC_DATA(NB_NBPS)

/* Nebula Dynamic Table's:
   Dynamic tables allocated at compiletime in a mergable way. */
#pragma pack(1)
__declspec(align(1)) typedef struct _NbTableEntry {
	void* AbsoluteAddress; // The address of a function or data (this is absolute)
	u32   SizeOfData;      // The size of the function or data
	                       // if its a function the size will be patched in by the builder
	union {
		struct {
			u8 IsFunction       : 1; // Defines if the entry describes a function
			u8 Nanomites        : 1; // Tells the builder to patch in nanomites for this function
			u8 EncryptObject    : 1; // Signals the builder to encrypt the function
			u8 RegisterFunction : 1; // Automatically registers the function for singlestep decryption
			u8 DecipherOnLoad   : 1; // the function is crypted but automatically decrypted on startup
			u8 Reserved         : 3; // reserved for future use (must be 0)
		};
		u8     Flags;
	} NbFFlags;
	u32   Vector[4];       // A KeyEntry, each crypted object can have its own key
} NbTableEntry;
#pragma pack()

#define NB_CRYPT 0x04
#define NB_NANO  0x02
#define NB_REGPG 0x08
#define NB_AUTOD 0x10

#pragma section(".nbft$ctableb", read)




#define NB_CMARKFUNCTION(FunctionAddress, FFFlags, EntryName)

#ifdef __cplusplus
template<int> struct NbCryptTable { static _NbTableEntry Entry; };
/* Creates a automatic nameless function entry in the nbft
   FunctionAddress : The address of the function for which an entry should be created
   FFlags          : These flags specify how the function should be treated by the runtime,
                     as well as what the builder should do with them */
#define N_CREATEFET(FunctionAddress, FFlags) ALLOC_DATA(".nbft$ctableb")\
constexpr NbTableEntry NbCryptTable<__COUNTER__>::Entry = { FunctionAddress, 0,  };
#define N_CREATEDET(DataAddress, Size) ALLOC_DATA(".nbft$ctableb")\
constexpr NbTableEntry NbCryptTable<__COUNTER__>::Entry = { DataAddress, 0, Size };

// Allocate nullterminating entry
#pragma section(".nbft$ctablez", read)
ALLOC_DATA(".nbft$ctablez") NbTableEntry NbCryptTable<__COUNTER__>::Entry = { null };
#else
ALLOC_DATA(".nbft$ctablez") NbTableEntry _Nb = { null };
#endif
#pragma endregion
#pragma endregion

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
