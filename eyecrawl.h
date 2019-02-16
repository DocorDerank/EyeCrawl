#pragma once
#ifndef C_EYECRAWL
#define C_EYECRAWL
#include <Windows.h>
#include <vector>

#define DLL_MODE FALSE
#define set_d(x,d){ x->dest=d; }
#define set_s(x,s){ x->src=s;  }
#define R_EAX 0
#define R_ECX 1
#define R_EDX 2
#define R_EBX 3
#define R_ESP 4
#define R_EBP 5
#define R_ESI 6
#define R_EDI 7

// Replaces any strings within a string, with
// another string based on an expression mask
std::string replaceex(std::string str, const char* replace, const char* mask, const char* newstr);

// Returns true if string A contains string B
bool strfind(const char* A, const char* B);


namespace EyeCrawl {
	void set(HANDLE);

	enum info_mode {
		show_none,
		show_offsets,
		show_ioffsets,
		show_int32,
		show_args,
		show_vars,
		show_args_and_vars,
		show_non_aslr
	};

	enum _m { // mnemonics
		none,		
		r8,			
		r16,		
		r32,		
		r16_32,		
		r_m8,		
		r_m16,		
		r_m32,		
		r_m16_32,	
		rel8,		
		rel16,		
		rel32,		
		imm8,		
		imm16,		
		imm32		
	};

	struct instruction {
		_m dest;// first opcode
		_m src;	// second opcode (based off type)

		char opcode[16];// opcode name
		char data[128]; // full instruction text
		int r8[4]; // 8bit registers used in instruction
		int r16[4];// 16bit registers used in instruction
		int r32[4];// 32bit registers used in instruction
		int size;
		int v8; // 8bit value moved into reg8/offset/etc.
		int v16;// 16bit value moved into reg16/offset/etc.
		int v32;// 32bit value moved into reg32/offset/etc.
		UINT_PTR offset;// offset value pulled from instruction if there is one

		instruction() {
			opcode[0]	= '\0';
			data[0]		= '\0';
			size		= 0; // skip over
			offset		= 0;
			v8			= 0;
			v16			= 0;
			v32			= 0;
			dest		= none;
			src			= none;
		}
	};

	typedef instruction* pinstruction;

	UINT_PTR aslr(UINT_PTR);
	UINT_PTR non_aslr(UINT_PTR);
	unsigned char readb(UINT_PTR);
	int readi(UINT_PTR);
	USHORT readus(UINT_PTR);
	UINT_PTR readui(UINT_PTR);
	
	pinstruction disassemble(UINT_PTR);
	std::string disassemble(UINT_PTR, int, info_mode);
}



#endif
