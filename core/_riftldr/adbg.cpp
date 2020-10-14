/* Anti Debugger */
#include "antire.h"

BOOL MSCheckForDebugger() {
    __try {
        DebugBreak();
    } __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ?
        EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        // No debugger is attached, so return FALSE
        // and continue.
        return FALSE;
    }
    return TRUE;
}