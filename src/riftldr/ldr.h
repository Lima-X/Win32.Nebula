#pragma once

// Merge const and nonconst data into one section
#pragma comment(linker, "/merge:.rdata=.data")

#include "shared.h"

namespace svc {
	poly ServiceCall(_In_range_(0, 0xffff) u32 svcId, _In_opt_ ...);
	poly ServiceDispatch(_In_range_(0, 0xffff) u32 svcId, _In_opt_ va_list val);
}