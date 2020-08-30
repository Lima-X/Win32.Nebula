#include "global.h"
#include "..\core\shared\shared.h"

namespace nid {
	void WrapHash(
		_Inout_ cry::Md5::hash hToWrap,
		_In_    cry::Md5::hash hWrap
	) {
		for (uint8 i = 0; i < sizeof(hToWrap); i++)
			((byte*)hToWrap)[i] ^= ((byte*)hWrap)[i];
	}
}