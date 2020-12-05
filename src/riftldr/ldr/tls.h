/* Special Header for .ldr (Packing-Engine) */
// The .ldr is seperated form teh normal standard Binary
#pragma once

#include "sub/sub.h"

// Linker->Commandline->Additional: "/MERGE:.ldrd=.ldr /MERGE:.ldrc=.ldr"
#pragma comment(linker, "/merge:.ldrd=.ldr")
#pragma comment(linker, "/merge:.ldrc=.ldr")

/* This Block has to enclose all code & data that belongs to the loaderstub

	#pragma code_seg(".ldr")
	#pragma data_seg(".ldrd")
	#pragma const_seg(".ldrc")
	namespace ldr {
		... <- Code here
	}
	#pragma data_seg()
	#pragma const_seg()
	#pragma code_seg()
*/

/* Everything that belongs to the loaderstub is stored within the ".ldr"-Section.
   The loaderstub has no access to the crt of the process,
   as the crt is stored inside the packed sections and therefore is incapable to use it,
   (using the crt would be unstable anyways as it is not initialized at TLS-Callback time) */