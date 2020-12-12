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
   S_: Severity   (Describes the State of the function)
   F_: Facility   (Describes which Part caused the issue)
   C_: Satus Code (Can be a predifined Value that idicates the problem)
   M_: Macros     (Preprocessor macros used to evaluate and create Status') */
#pragma once

/*        | Status-Format: (32 bit Type)
----------+----------+-----------+-------------------------
Property: | Severity | Facility  | Status Code
Mask:     | BB       | BBBBBBBB  | BBBBBBBBBBBBBBBBBBBBBBBB
----------+----------+-----------+-------------------------
Size:     | 2 bits   | 6 bits    | 24 bits    (3 bytes)
Value:    | 0x3 (4)  | 0x3f (64) | (0xffffff) (16777216) */
typedef _Success_(!(return & (0b1 << 31))) signed long status;
/* typedef struct _status {
    dword Code     : 24;
    dword Facility :  6;
    dword Severity :  2;
} status, * pstatus; */

#pragma region Severity
#define S_SUCCESS 0b00 // Indicates a successful execution
#define S_MESSAGE 0b01 // Return Value format unspecified, depends on the function
                       // (lower 30 bits available for use by the function)

#define S_WARNING 0b10 // Indicates that a Subroutine migth have failed partially,
                       // Data might be incomplete and cause further Errors.
#define S_ERROR   0b11 // Indicates that the Subroutine failed.
#pragma endregion

#pragma region Facility
#define F_NULL    0 // Undefined Facility (can be used anywhere (often used for utility functions))
#define F_LOADER  1 // Code run inside riftldr at Stage-1 (crypter and protections)
#define F_MAIN    2 // Code from the rift core (Stage-2 Entrypoint: CoreMain)

#define F_ROOTKIT 4 // Code from the Rootkit Module (riftrk.dll)
#define F_BUILDER 6 // Code from the Build Tool and Patcher (riftbld.exe)

// Facility Codes from 0-15 are reserved for Nebula

#define F_CLIENT 16 // 16 - 63 are reserved for the client
#pragma endregion

#pragma region Status Codes
#define C_NULL 0            // No Code Specified (can be used if no errorinformation is available, should be used when S_SUCCESS)
#define C_INVALID_POINTER 1 // Pointer to Object is invalid (NullPointer)
#define C_THREAD_DIED     2 // A important Asynchronous Thread died prematurely


#define C_CLIENT 65536 // Status Codes from 65536 (0x10000) - 16777216 (0xffffff) are reserved for the Client
#pragma endregion

#pragma region Status Macros
#define M_SUCCESS(s) !(s >> 31)          // Checks if status idicates no Issues (neither an Error nor Warning)
#define M_ERROR(s) ((s >> 30) & S_ERROR) // Checks if status idicates an Error
#define M_WARNING(s) (s >> 31)           // Checks if status Idicates an Issue (this includes Errors)

// Used to generate a Status
#define M_CREATE(Severity, Facility, Code) ((Severity << 30) |\
                                           ((Facility & 0x3f) << 24) |\
                                           (Code & 0xffffff))

// Used to convert function defined data to a status of type S_MESSAGE
#define M_MESSAGE(Data) (S_MESSAGE << 30 |\
                         Data & 0x3fffffff)
#pragma endregion
