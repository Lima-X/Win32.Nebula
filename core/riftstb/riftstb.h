#pragma once

#include "shared.h"

/* RPC DebugObject UAC Bypass/Exploit */
#ifndef __cplusplus
#pragma comment(lib, "rpcrt4.lib")
#include <rpcndr.h>
#include <rpc.h>
#include <oaidl.h>
#include <ocidl.h>
#include "appinfo32.h"
#endif

#ifdef __cplusplus
namespace svc {
	long svcCall(_In_range_(0, 0x1fff) uint16 svcId, _In_opt_ ...);
}
#endif
