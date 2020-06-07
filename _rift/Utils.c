#include "pch.h"
#include "_rift.h"

BOOL fnIsUserAdmin() {
	PSID pSId;
	BOOL bSId = AllocateAndInitializeSid(&(SID_IDENTIFIER_AUTHORITY)SECURITY_NT_AUTHORITY, 2,
		SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSId);
	if (bSId) {
		if (!CheckTokenMembership(0, pSId, &bSId))
			bSId = FALSE;

		FreeSid(pSId);
	}

	return bSId;
}

PVOID fnLoadResourceW(
	_In_  WORD    wResID,
	_In_  PCWSTR  pResType,
	_Out_ PSIZE_T nBufferSize
) {
	HRSRC hResInfo = FindResourceW(0, MAKEINTRESOURCEW(wResID), pResType);
	if (hResInfo) {
		HGLOBAL hgData = LoadResource(0, hResInfo);
		if (hgData) {
			PVOID lpBuffer = LockResource(hgData);
			if (!lpBuffer)
				return 0;

			*nBufferSize = SizeofResource(0, hResInfo);
			if (!*nBufferSize)
				return 0;

			return lpBuffer;
		}
	}

	return 0;
}