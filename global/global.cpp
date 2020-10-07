#include "global.h"

namespace nid {
	// Dummy for hash datatype (Md5 class will be moved here in the future)
	namespace cry {
		class Md5 {
		public:
			typedef GUID hash;
		};
	}

	void WrapHash(
		_Inout_ cry::Md5::hash hToWrap,
		_In_    cry::Md5::hash hWrap
	) {
		for (uint8 i = 0; i < sizeof(hToWrap); i++)
			(*(byte**)&hToWrap)[i] ^= (*(byte**)&hWrap)[i];
	}
}

// This contains utilities for debugging (only implemented in Debug config)
#ifdef _DEBUG
LARGE_INTEGER Benchmark::m_liFrequenzy;
#endif
Benchmark::Benchmark(
	_In_ Resolution res
)
#ifdef _DEBUG
	: m_res(res) {
	if (!m_liFrequenzy.QuadPart)
		QueryPerformanceFrequency(&m_liFrequenzy);
#else
	{
	#endif
}

void Benchmark::Begin() {
#ifdef _DEBUG
	QueryPerformanceCounter(&m_liBegin);
#endif
}
// (yes this uses the 64bit integers on 32bit arch (its ok for debugging))
uint64 Benchmark::End() {
#ifdef _DEBUG
	QueryPerformanceCounter(&m_liEnd);

	// Calculate time difference, whole and part
	m_liEnd.QuadPart -= m_liBegin.QuadPart;
	uint64 Whole = (m_liEnd.QuadPart / m_liFrequenzy.QuadPart) * (uint64)m_res;
	uint64 Part = (m_liEnd.QuadPart % m_liFrequenzy.QuadPart) * (uint64)m_res;
	Part /= m_liFrequenzy.QuadPart;

	return Whole + Part;
#endif
}
