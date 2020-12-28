/* Defines the Statussystem of Nebula, its Values and Macors
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
   SC_: Satus Code (Can be a predifined Value that idicates the problem) */
#pragma once

/*        | Status-Format: (32-Bit Type)                    | Severity Format: (2-Bits)
----------+----------+-----------+------------------------- | -------------------------
Property: | Severity | Facility  | Status Code              | B[1 (31)] : Error-Flag
Mask:     | BB       | BBBBBBBB  | BBBBBBBBBBBBBBBBBBBBBBBB | Indicates a Problem
----------+----------+-----------+------------------------- | B[0 (30)] : Special-Flag
Size:     | 2 bits   | 6 bits    | 24 bits    (3 bytes)     | Special treatment needed
Value:    | 0x3 (4)  | 0x3f (64) | (0xffffff) (16777216)    |                        */
typedef _Success_(!(return & (0b1 << 31))) signed long status;
/* typedef struct _status {
    dword Code     : 24;
    dword Facility :  6;
    dword Severity :  2;
} status, * pstatus; */
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
#define SF_NULL    0 // Undefined Facility (can be used anywhere (often used for utility functions))
#define SF_LOADER  1 // Code run inside riftldr at Stage-1 (crypter and protections)
#define SF_MAIN    2 // Code from the rift core (Stage-2 Entrypoint: CoreMain)

#define SF_ROOTKIT 4 // Code from the Rootkit Module (riftrk.dll)
#define SF_BUILDER 6 // Code from the Build Tool and Patcher (riftbld.exe)

// Facility Codes from 0-15 are reserved for Nebula

#define SF_CLIENT 16 // 16 - 63 are reserved for the client
#pragma endregion

#pragma region Status Codes
#define SC_NULL                0 // No Code Specified (can be used if no errorinformation is available, should be used when S_SUCCESS)
#define SC_UNKNOWN             1 // A unknown issue occurred
#define SC_THREAD_DIED         2 // A important Asynchronous Thread died prematurely
#define SC_INVALID_PARAMETER   3 // A Parameter of a Functioncall was Invalid
#define SC_UNHANDLED           4 // A request remains unhandled
#define SC_SEARCH_UNSUCCESSFUL 5 // A search that was attempted faild or found no result
#define SC_INVALID_POINTER     6 // Pointer to Object is invalid (NullPointer)
#define SC_INVALID_DATA        7 // Invalid/Malformed data was found
#define SC_UNSUPPORTED         8 // A unsupported feature was requested
#define SC_INVALID_HANDLE      9 // A invalid handle was found/translated
#define SC_COULDNT_ATTACH     10 // Could not attach to protocol
#define SC_INCOMPLETE         11 // Opearation remains incomplete



#define SC_CLIENT 65536 // Status Codes from 65536 (0x10000) - 16777216 (0xffffff) are reserved for the Client
#pragma endregion

#pragma region Status Macros
#define S_SEVERITY(s) (s >> 30)           // Gets the Serverity Flags
#define S_SUCCESS(s)  !(s >> 31)          // Checks if status idicates no Issues (neither an Error nor Warning)
#define S_WARNING(s)  ((s >> 30) == 0b11) // Checks if status idicates an Warning
#define S_ERROR(s)    ((s >> 30) == 0b10) // Checks if status idicates an Error
#define S_ISSUE(s)    (s >> 31)           // Checks if status Idicates an Issue (this includes Errors)

// Used to generate a Status
#define S_CREATE(Severity, Facility, Code) ((Severity << 30) |\
                                           ((Facility & 0x3f) << 24) |\
                                           (Code & 0xffffff))

// Used to convert function defined data to a status of type S_MESSAGE
#define S_CREATEM(Data) (SS_MESSAGE << 30 |\
                         Data & 0x3fffffff)
#pragma endregion
