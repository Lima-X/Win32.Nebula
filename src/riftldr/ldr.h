#pragma once

#include "shared.h"

namespace svc {
	poly ServiceCall(_In_range_(0, 0xffff) u32 svcId, _In_opt_ ...);
	poly vServiceCall(_In_range_(0, 0xffff) u32 svcId, _In_opt_ va_list val);
}