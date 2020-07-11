#pragma once

#include "..\_riftldr\depends.h"

#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)

/* RPC DebugObject UAC Bypass/Exploit */
#pragma comment(lib, "rpcrt4.lib")
#include <rpcndr.h>
#include <rpc.h>
#include <oaidl.h>
#include <ocidl.h>
#include "appinfo32.h"

#include "..\shared\shared.h"

// Why did i even bother making this macro for this
// if this file doesn't get used outside the dll anyways -.-
#ifdef _WINDLL
#define DLLEX __declspec(dllexport)
#else
#define DLLEX __declspec(dllimport)
#endif // _WINDLL

DLLEX BOOL EDllInit(_In_ PPIB pib);