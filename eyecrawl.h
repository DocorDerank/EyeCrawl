#pragma once
#ifndef C_EYECRAWL
#define C_EYECRAWL
#include <Windows.h>
#include <vector>

#define DLL_MODE FALSE
#define set_d(x,d){ x->dest=d; }
#define set_s(x,s){ x->src=s;  }
#define results std::vector<UINT_PTR>
#define STR_READ_MAX 1024
#define PMREAD ReadProcessMemory
#define PMWRITE WriteProcessMemory
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
	void set(HANDLE);	// Use for remote application
	void set();			// Use for DLL mode
	HANDLE get();
	UINT_PTR base_start();
	UINT_PTR base_end();

	enum dir {
		ahead,
		behind
	};

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
		r_m16_32,	
		rel8,		
		rel16,		
		rel32,		
		imm8,		
		imm16,		
		imm32,		
		rxmm		
	};

	struct instruction {
		_m dest;// first opcode
		_m src;	// second opcode (based off type)

		char opcode[16];// opcode name
		char data[128]; // full instruction text
		int r8[4]; // 8bit registers used in instruction
		int r16[4];// 16bit registers used in instruction
		int r32[4];// 32bit registers used in instruction
		int rxmm[4];// xmm/FPU registers used in instruction
		int size;
		int v8; // 8bit value moved into reg8/offset/etc.
		int v16;// 16bit value moved into reg16/offset/etc.
		int v32;// 32bit value moved into reg32/offset/etc.
		UINT_PTR offset;// offset value pulled from instruction if there is one
		UINT_PTR address;// current address of this instruction
		char mark1[16];// byte ptr/dword ptr/qword ptr for first operand
		char mark2[16];// same as above but will show for second operand

		instruction() {
			opcode[0]	= '\0';
			data[0]		= '\0';
			mark1[0]	= '\0';
			mark2[0]	= '\0';
			size		= 0; // skip over
			offset		= 0;
			v8			= 0;
			v16			= 0;
			v32			= 0;
			dest		= none;
			src			= none;
			address		= 0;
		}
	};

	typedef instruction* pinstruction;

	UINT_PTR	aslr(UINT_PTR);
	UINT_PTR	non_aslr(UINT_PTR);

	// memory reading
	UCHAR		readb(UINT_PTR);
	char		readc(UINT_PTR);
	USHORT		readus(UINT_PTR);
	short		reads(UINT_PTR);
	UINT_PTR	readui(UINT_PTR);
	int			readi(UINT_PTR);
	float		readf(UINT_PTR);
	double		readd(UINT_PTR);
	std::string sreads(UINT_PTR, int);
	
	// memory writing
	bool		write(UINT_PTR, UCHAR);
	bool		write(UINT_PTR, char);
	bool		write(UINT_PTR, USHORT);
	bool		write(UINT_PTR, short);
	bool		write(UINT_PTR, UINT_PTR);
	bool		write(UINT_PTR, int);
	bool		write(UINT_PTR, float);
	bool		write(UINT_PTR, double);
	bool		write(UINT_PTR, std::string);
	
	pinstruction disassemble(UINT_PTR);
	std::string  disassemble(UINT_PTR, int, info_mode);

	// Utilities for debugging/scanning/getting functions/etc.
	// WIP
	//
	namespace util {
		struct MEM_PROTECT {
			MEMORY_BASIC_INFORMATION protection_data;
			UINT_PTR address;
			ULONG_PTR size;
		};

		std::string to_str(UINT_PTR);
		std::string to_str(UCHAR);
		UCHAR to_byte(char*);
		// Reads the value of a 32bit register, or an
		// offset of the register, at the given address.
		// 
		// It does this via a hook, which gets swapped out
		// immediately afterwards
		// Instructions partially overwritten
		// are taken care of.
		// 
		// You can thank static for this awesomeness (static#8737)
		// 
		UINT_PTR debug32(UINT_PTR, UCHAR, int);

		// allocates virtual memory
		// at a random location,
		// with EXECUTE_READWRITE access
		UINT_PTR valloc(ULONG_PTR);
		// frees allocated virtual memory
		bool vfree(UINT_PTR, ULONG_PTR);

		// Grants EXECUTE_READWRITE access to a
		// location in memory
		MEM_PROTECT vprotect(UINT_PTR location, ULONG_PTR size);
		// Restores page access to a location
		// in memory
		void vrestore(MEM_PROTECT protection);

		// used for identifying function marks
		bool isprologue(UINT_PTR);
		bool isepilogue(UINT_PTR);
		UINT_PTR getepilogue(UINT_PTR);
		results getepilogues(UINT_PTR);
		UINT_PTR nextprologue(UINT_PTR, dir, bool);
		UINT_PTR nextepilogue(UINT_PTR, dir);

		short fretn(UINT_PTR);
		int fsize(UINT_PTR);
		results getcalls(UINT_PTR);

		// gets the next call instruction
		// and returns either the address of the call(loc=true),
		// or the function it is calling(loc=false).
		UINT_PTR nextcall(UINT_PTR, dir, bool loc);

		// Determines calling convention of a function
		std::string calltype(UINT_PTR);

		// Scans memory for an array of bytes (AOB)
		// Extremely efficient
		// Use base_start() and base_end()
		// for any x86-related scans
		// 
		results scan(UINT_PTR, UINT_PTR, const char*, const char*);
		results scan(UINT_PTR, UINT_PTR, const char*);
	};
}



#endif
