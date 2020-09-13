#pragma once

#include "..\shared\shared.h"

#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)

/* RPC DebugObject UAC Bypass/Exploit */
#ifndef __cplusplus
#pragma comment(lib, "rpcrt4.lib")
#include <rpcndr.h>
#include <rpc.h>
#include <oaidl.h>
#include <ocidl.h>
#include "appinfo32.h"
#endif

// Why did i even bother making this macro for this
// if this file doesn't get used outside the dll anyways -.-
#ifdef _WINDLL
#define DLLEX __declspec(dllexport)
#else
#define DLLEX __declspec(dllimport)
#endif // _WINDLL

#ifdef __cplusplus
DLLEX BOOL EDllInit(_In_ PIB* pib);
#endif