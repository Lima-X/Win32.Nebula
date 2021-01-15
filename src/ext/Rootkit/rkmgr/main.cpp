#include "mgr.h"

status ExtensionEntry(            // Entrypoint-Callback for nebula mapper
	_In_        u32  CallbackId,  // The id of the callback function requested
	_Inout_opt_ poly CallbackData // Callback specific data that should be interpreted by the propeer handler
) {
	switch (CallbackId) {



	default:
		return S_CREATE(SS_WARNING, SF_ROOTKIT, SC_UNSUPPORTED);
	}

	return SUCCESS;
}