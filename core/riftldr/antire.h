#pragma once
#include "global.h"

// Windows special Headers
#include <psapi.h>
#include <tlHelp32.h>

// Windows unlinked Headers
#pragma comment(lib, "bcrypt.lib")
#include <bcrypt.h>

// Microsoft Detours
#pragma comment(lib, "..\\..\\other\\msDetours\\lib.X86\\detours.lib")
#include "..\..\other\msDetours\include\detours.h"

// Dummyclass for typedef to get correct linkage
namespace cry { class Hash { public: typedef GUID hash; }; }
namespace dat {
	/* Contains the expected Hash of Section in the Image.
	   This is only a Signature and has to be patched out with _riftutl.
	   Patchable-Signature: "dat:SIG.MemHash" */
	constexpr cry::Hash::hash hMemoryHash = { ':tad', 'IS', '.G', { 'M', 'e', 'm', 'H', 'a', 's', 'h', '\0' } };
}
