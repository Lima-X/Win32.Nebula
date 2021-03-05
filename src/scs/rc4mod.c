// rc4mod shellcode, compile with: >cl /c /O2 /Oi /GS-
#include <sal.h>

// Integer Types
typedef unsigned char      u8;
typedef unsigned long      u32;
typedef unsigned long long u64;

/* Config Format:
   BBBBBBBB|BBBBBBBB | BBBBBBBBB | BBBBBBBB|BBBBBBBB | B | BBBBBBBBBBBBBBBB
   ctx.i :8 ctx.j :8 | keylen :9 | SBoxOff  OffsetBa |   | Zerorounds   :16

   Region Format:
   BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB | BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
   Offset relative to base      :32 | size of region               :32   */
#define OFFSETBASE 17
#define SBOXINIT   25
#define KEYLEN     33
#define CTXJ       42
#define CTXI       50



__forceinline void swap8( // Swaps 2 bytes
	_In_ u8* x,           // byte 1
	_In_ u8* y            // byte 2
) {
	// y = _InterlockedExchange8(x, *y);
	u8 k = *x;
	*x = *y;
	*y = k;
}



typedef struct _rc4ctx { // RC4 Context
	u8 SBox[256];        // The Substitution-Box
	u8 i, j;             // RC4 SBox-State
} rc4ctx;

__forceinline void ksa(                   // KeyStream-Scheduling-Algorithm (KSA)
	_In_               rc4ctx* ctx,       // RC4 internal context
	_In_               void*   KeyStream, // The key used to initialize the state
	_In_range_(1, 256) int     KeyLength  // The length of the key to use in bytes
) {
	for (int i = 0; i < 256; i++)
		ctx->SBox[ctx->i++] = i;
	for (int i = 0; i < 256; i++) {
		ctx->j += ctx->SBox[i] + ((u8*)KeyStream)[i % KeyLength];
		// swap8(&ctx->SBox[i], &ctx->SBox[ctx->j]);
		ctx->SBox[i] = _InterlockedExchange8(&ctx->SBox[ctx->j], ctx->SBox[i]);
	}
}
__forceinline u8 prg(   // Pseudo-Random-Generation (PRG)
	_In_ rc4ctx* ctx,   // RC4 internal context
	_In_ u8      Offset // has to be coprime realative to 256 (optimal 15)
) {
	ctx->j = (ctx->i += Offset) + ctx->SBox[ctx->i];               // Modified SBox Translation
	// swap8(&ctx->SBox[ctx->i], &ctx->SBox[ctx->j]);              // Mutate SBox by swap
	ctx->SBox[ctx->i] = _InterlockedExchange8(&ctx->SBox[ctx->j], ctx->SBox[ctx->i]);
	return ctx->SBox[(u8)(ctx->SBox[ctx->i] + ctx->SBox[ctx->j])]; // Resolve output byte
}

void crypt(               // Crypts a buffer with RC4 cipher (RC4 modification)
	_Inout_ void* Buffer, // The input data to be crypted
	_In_    u64   Region, // The area of the input to be ciphered
	_In_    void* Key,    // The key to be used in the encryption
	_In_    u64   Config  // describes how the algorithim is scheduled
) {
	// Initialize context
	rc4ctx ctx;
	ctx.i = Config >> SBOXINIT & 0xff;
	ctx.j = Config >> CTXJ & 0xff;
	ksa(&ctx, Key, Config >> KEYLEN & 0x1ff);

	// ZeroRounds
	ctx.i = Config >> CTXI & 0xff;
	u8 w = Config >> OFFSETBASE & 0xff;
	while (Config-- & 0xffff)
		prg(&ctx, w);
	u32 rva = Region >> 32;
	(u64)Buffer += rva;
	while(rva--)
		prg(&ctx, w);

	// Crypt Buffer
	while (Region-- & ~0ul)
		*((u8*)Buffer)++ ^= prg(&ctx, w);
}