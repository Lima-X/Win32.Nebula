/* This File serves as the absolute base of the whole project for other headers to build on */
#pragma once

// Disable Useless/Inaccurate Warnings
#pragma warning(disable : 4100)
#pragma warning(disable : 4200)
#pragma warning(disable : 4267)
#pragma warning(disable : 4302)
#pragma warning(disable : 4311)
#pragma warning(disable : 4595)
#pragma warning(disable : 4706)

#pragma region Base
// Language (C/C++) Specific
#if !_NSDK
#define _CRT_SECURE_NO_WARNINGS        // Disables insecure CRT feature warnings (because we dont care)
#define _VCRTIMP __declspec(dllimport) // Shitty hack in order to prevent the compiler from complain about
                                       // C++ overloaded inline functions being "redefined" by importing
#include <intrin.h>                    // Intrinsics (this is redundant as the windows header also includes this)

// Windows (NT) Specific
#define  WIN32_LEAN_AND_MEAN            // Reduce Header Size
#endif
#define _WIN32_WINNT         0x06000000 // Windows Vista and up
#include <windows.h>                    // Windows Header
#include <winternl.h>                   // Windows Internals
#pragma endregion

/* Nebula Specific *///////////////////////////////
// Defines Common/Standard Datatypes used by Nebula
#pragma region Definitions
#pragma region Datatype Declarations
// Standard Types for Strings
typedef          wchar_t   wchar;

// Integer Types
typedef          char      i8;
typedef          short     i16;
typedef          int       i32;
typedef          long long i64;
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

// CPU Types
typedef unsigned char      byte;
typedef unsigned short     word;
typedef unsigned long      dword;
typedef unsigned long long qword;

// Pointer Types
#ifdef _M_X64
typedef unsigned long long ptr;    // A pointer as a raw value used for pointer arithmetic (prefered over "void*")
typedef unsigned long long poly;   // A polymorthic scalar type that can be used to store anything fitting
typedef          void*     handle; // A handle is a polymorthic type that stores a reference or value associated to an object
                                   // this value has to be translated and processed by the corresponding api (similar to WinAPI's)
#elif _M_IX86
typedef unsigned long  ptr;
typedef unsigned long  poly;
typedef          void* handle;
#endif
#pragma endregion

#pragma region Standard Macros
#ifdef  _M_X64
#define __x64call
#else
#define __x64call INVALID_CALLING_CONVENTION // This cause a compiler error
#endif

#define GENERIC_READWRITE      0xc0000000 // (GENERIC_READ | GENERIC_WRITE)
#define MEM_ALLOC              0x00003000 // (MEM_RESERVE | MEM_COMMIT)

#define DEPRECATED             __declspec(deprecated)
#define DEPRECATED_STR(String) __declspec(deprecated(String))

#define IMPORT                 __declspec(dllimport)
#define EXPORT                 __declspec(dllexport)
#define NOINLINE               __declspec(noinline)

#define ALLOC_CODE(Section)    __declspec(code_seg(Section))
#define ALLOC_DATA(Section)    __declspec(allocate(Section))
#pragma endregion
#pragma endregion

#pragma region Status System
/* Defines the Statussystem of Nebula, its Values and Macros
   Guideline:
       All Functions in Nebula that can fail or are required to return data to the caller
       return a value of type "status".
       If a function has to return special info to the caller it can do so through status using MOREINFO
       if the data fits within 30bits (preferably only 24bits (3bytes)),
       else it has to return that data through parameter(s) by reference.

       Fucntions that can NOT fail dont have to return "status" and can instead return nothing (void),
       they can also return a polymorphic type like "poly" or a pointer (preferably void* or ptr).

       NOTE: These Guidelines do not apply to Systemcallbacks from the WinAPI

   Macro Prefixes:
   S_:  Macor's    (Macros to create and evaluate status')
   SS_: Severity   (Describes the State of the function)
   SF_: Facility   (Describes which Part caused the issue)
   SC_: Satus Code (Can be a predifined Value that idicates the problem)

             | Status-Format: (32-Bit Type)                    | Severity Format: (2-Bits)
   ----------+----------+-----------+------------------------- | -------------------------
   Property: | Severity | Facility  | Status Code              | B[1 (31)] : Error-Flag
   Mask:     | BB       | BBBBBB    | BBBBBBBBBBBBBBBBBBBBBBBB | Indicates a Problem
   ----------+----------+-----------+------------------------- | B[0 (30)] : Special-Flag
   Size:     | 2 bits   | 6 bits    | 24 bits    (3 bytes)     | Special treatment needed
   Value:    | 0x3 (4)  | 0x3f (64) | (0xffffff) (16777216)    |                        */
typedef _Success_(!(return & (0b1 << 31))) signed long status;
/* typedef struct _status {
    dword Code     : 24;
    dword Facility :  6;
    dword Severity :  2;
} status, * pstatus;  */
#define SUCCESS 0 // returned by a routine when successful and no further info is provided

#pragma region Severity
#define SS_SUCCESS 0b00 // Indicates a successful execution
#define SS_MESSAGE 0b01 // Return Value format unspecified, depends on the function
                        // (lower 30 bits available for use by the function)

#define SS_ERROR   0b10 // Indicates that the subroutine failed.
#define SS_WARNING 0b11 // Indicates that a subroutine migth have failed partially,
                        // Data might be incomplete and could cause further errors.
#pragma endregion

#pragma region Facility
// Facility-Codes from 0-15 are reserved for Nebula ()
#define SF_NULL    0 // Undefined Facility (can be used anywhere (often used for utility functions))
#define SF_LOADER  1 // Code run inside riftldr at Stage-1 (crypter and protections)
#define SF_CORE    2 // Code from the rift core (Stage-2 Entrypoint: CoreMain)
#define SF_BUILDER 7 // Code from the Build Tool and Patcher (riftbld.exe)

// Facility-Codes 16 - 63 are reserved for the client
#define SF_CLIENT  16 //

#define SF_RKCMGR  16 // Code from the Rootkit Control Manager Extension (rkmgr.ext)
#define SF_ROOTKIT 17 // Code from the Rootkit Module (riftrk.dll)
#pragma endregion

#pragma region Status Codes
#define SC_NULL                0 // No Code Specified (can be used if no errorinformation is available, should be used when SS_SUCCESS)
#define SC_UNKNOWN             1 // A unknown issue occurred
#define SC_THREAD_DIED         2 // A important Asynchronous Thread died prematurely
#define SC_INVALID_PARAMETER   3 // A Parameter of a Functioncall was Invalid
#define SC_UNHANDLED           4 // A request remains unhandled
#define SC_SEARCH_UNSUCCESSFUL 5 // A search that was attempted failed or found no result
#define SC_INVALID_POINTER     6 // Pointer to Object is invalid (NullPointer)
#define SC_INVALID_DATA        7 // Invalid/Malformed data was found
#define SC_UNSUPPORTED         8 // A unsupported feature was requested
#define SC_INVALID_HANDLE      9 // A invalid handle was found/translated
#define SC_COULDNT_ATTACH     10 // Could not attach to protocol
#define SC_INCOMPLETE         11 // Opearation remains incomplete
#define SC_INVALID_SIZE       12 // Invalid size parameter
#define SC_INVALID_COMMAND    13 // An invalid command was requested
#define SC_NOT_FOUND          14 // The element searched for was not found
#define SC_ALREADY_EXISTS     15 // Object already exists
#define SC_INVALID_SIGNATURE  16 // A signature to validate an object did not match

#define SC_CLIENT 65536 // Status Codes from 65536 (0x10000) - 16777216 (0xffffff) are reserved for the Client
#pragma endregion

#pragma region Status Macros
#define S_SEVERITY(s)  (s >> 30)           // Gets the Serverity Flags
#define S_FACILITY(s)  ((s >> 24) & 0x3f)  // Gets the Facility Id
#define S_CODE(s)      (s & 0xffffff)      // Gets the Statuscode
#define S_MESSAGE(s)   (s & 0x3fffffff)    // Gets the Message

#define S_SUCCESS(s)   !(s >> 31)          // Checks if status idicates no Issues (neither an Error nor Warning)
#define S_WARNING(s)   ((s >> 30) == 0b11) // Checks if status idicates an Warning
#define S_ERROR(s)     ((s >> 30) == 0b10) // Checks if status idicates an Error
#define S_ISMESSAGE(s) ((s >> 30) == 0b01) // Checks if status is a function specific message
#define S_ISSUE(s)     (s >> 31)           // Checks if status Idicates an Issue (this includes Errors)

// Used to generate a Status
#define S_CREATE(Severity, Facility, Code) ((Severity << 30) |\
                                           ((Facility & 0x3f) << 24) |\
                                           (Code & 0xffffff))

// Used to convert function defined data to a status of type S_MESSAGE
#define S_CREATEM(Data) (SS_MESSAGE << 30 |\
                         Data & 0x3fffffff)
#pragma endregion
#pragma endregion


// The Macroprefix "N_" is reserved for Nebula's usage
#pragma region Import FNV-1a Hashes
#define N_NTDLL     0xfd96b5caa3a9c6d9 // L"ntdll.dll"
#define N_NTQUERYSI 0xcac033026619e14a // "NtQuerySystemInformation"
#define N_NTQUERYDF 0x9859ea27eda9b57e // "NtQueryDirectoryFile"
#define N_RTLCOMBUF 0x2f3a7db33e2ae08b // "RtlCompressBuffer"
#define N_RTLDECBUF 0xf4e7dfe9f97daee1 // "RtlDecompressBufferEx"
#define N_RTLCOMWWS 0x2f4628d5a07bd77d // "RtlGetCompressionWorkSpaceSize"
#define N_RTLRANDEX 0xa12ac26abe63b26f // "RtlRandomEx"
#define N_NTQUERYVM 0x8ef72532eaeee49f // "NtQueryVirtualMemory"
// #define N_CRTWCSCAT 0x48400801361a0cf8 // "wcscat"
// #define N_CRTWCSLWR 0x830509af3f20a316 // "_wcslwr"

// Nebula Hashses:
#define N_ADDEXCLUS 0x165dc6731b1c1c81 // "AddMemoryRegionExclusion"
#define N_REMEXCLUS 0x10e5c1ef8abb14e2 // "RemoveMemoryRegionExclusion"
#define N_SCANVASPC 0xabd01abea3896cb0 // "ScanUserModeVirtualMemory"


// Kernel32 will likely never beused as ntdll is prefered for all hidden functions
#define N_KRNL32DLL 0x7f1bf8b449d16c2d // L"kernel32.dll"

#if 0 // Bcrypts usage has been stripped from the project, reasons:
      // 1. usign aes or sha for anything here is just too overkill
      // 2. It would require to import another library
      // 3. In order to hide shit properly the Imports all would have to be Dynamic
      // 4. Hashed Imports are fast but still alot slower compared to nt!LdrXxx
      // 5. Same Reasons as why im not using cabinet (bcrypt doesnt support all features on all platforms)
      //    Nebula is meant to work on all nt6 systems, so i prefer to just do shit myself instead
#define N_BCRYPTDLL 0x589716db3c6ad2b1 // L"bcrypt.dll"
#define N_BCCALGPRO 0xd05325edc3942847 // "BCryptCloseAlgorithmProvider"
#define N_BCCREHASH 0xd577120aeac34017 // "BCryptCreateHash"
#define N_BCDECRYPT 0xe813f52a0c1eb360 // "BCryptDecrypt"
#define N_BCDESHASH 0x1256b5291ddc435f // "BCryptDestroyHash"
#define N_BCDESTKEY 0x456e49222c4e5716 // "BCryptDestroyKey"
#define N_BCENCRYPT 0x7cfbe1a0e01ab5e4 // "BCryptEncrypt"
#define N_BCEXPORTK 0xd7a3e1547e22b7a4 // "BCryptExportKey"
#define N_BCFINHASH 0xbd0e01391378b228 // "BCryptFinishHash"
#define N_BCGENSYMK 0xd0258dee7a62b6ba // "BCryptGenerateSymmetricKey"
#define N_BCGENRAND 0x81b17a4c9b61eeac // "BCryptGenRandom"
#define N_BCGETPROP 0xded8482b3d5effb4 // "BCryptGetProperty"
#define N_BCHASHDAT 0x96d6540c2cfbfbf7 // "BCryptHashData"
#define N_BCIMPORTK 0x6fd72c3b719e9b35 // "BCryptImportKey"
#define N_BCOALGPRO 0x1e7273483b28159d // "BCryptOpenAlgorithmProvider"
#define N_BCSETPROP 0xaf4ca6dc1939de68 // "BCryptSetProperty"
#endif
#pragma endregion
