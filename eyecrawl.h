#ifndef C_EYECRAWL_x86
#define C_EYECRAWL_x86
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>

#define RESULTS std::vector<UINT_PTR>
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

namespace EyeCrawl {
	// Use OpenProcess to get your handle if using on
	// a remote process.
	// Use open(NULL) if you are using a DLL!
	void open(HANDLE);
	HANDLE get();
	UINT_PTR base_start();
	UINT_PTR base_end();
	UINT_PTR aslr(UINT_PTR);
	UINT_PTR non_aslr(UINT_PTR);

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
		single,
		cnd8,
		cnd16,
		cnd32,
		r_m,
		r8,
		r16,
		r32,
		r_m8,
		r_m16,
		r_m32,
		rel8,
		rel16,
		rel32,
		imm8,
		imm16,
		imm32,
		rxmm,
		r_mx,
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
			opcode[0] = '\0';
			data[0] = '\0';
			mark1[0] = '\0';
			mark2[0] = '\0';
			size = 0; // skip over
			offset = 0;
			v8 = 0;
			v16 = 0;
			v32 = 0;
			dest = none;
			src = none;
			address = 0;
		}
	};

	struct instruction_ref {
		UCHAR bytes[8];
		char opcode[16];
		int size;
		_m dest;
		_m src;
		char mark1[16];
		char mark2[16];
		int div;

		instruction_ref(std::vector<UCHAR>_bytes,int _div,const char* _opcode,_m _dest,_m _src,const char* _mark1,const char* _mark2){
			size	= _bytes.size();
			dest	= _dest;
			src		= _src;
			div		= _div;
			memcpy(bytes,_bytes.data(),size);
			strcpy_s(opcode, _opcode);
			strcpy_s(mark1, _mark1);
			strcpy_s(mark2, _mark2);
		}
	};

	typedef instruction* pinstruction;
	pinstruction disassemble(UINT_PTR);
	std::string  disassemble(UINT_PTR, int, info_mode);
	std::string to_str(UINT_PTR);
	std::string to_str(UCHAR);
	UCHAR to_byte(char*);

	// memory reading
	UCHAR		readb(UINT_PTR);
	char		readc(UINT_PTR);
	USHORT		readus(UINT_PTR);
	short		reads(UINT_PTR);
	UINT_PTR	readui(UINT_PTR);
	int			readi(UINT_PTR);
	float		readf(UINT_PTR);
	double		readd(UINT_PTR);
	std::string sreads(UINT_PTR);

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

	// Utilities for debugging/scanning/getting functions/etc.
	// WIP
	//
	namespace util {
		struct MEM_PROTECT {
			MEMORY_BASIC_INFORMATION protection_data;
			UINT_PTR address;
			ULONG_PTR size;
		};

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
		RESULTS getepilogues(UINT_PTR);
		UINT_PTR nextprologue(UINT_PTR, dir, bool);
		UINT_PTR nextepilogue(UINT_PTR, dir);

		short fretn(UINT_PTR);
		int fsize(UINT_PTR);
		RESULTS getcalls(UINT_PTR);

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
		RESULTS scan(UINT_PTR, UINT_PTR, const char*, const char*);
		RESULTS scan(UINT_PTR, UINT_PTR, const char*);

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
		RESULTS debug32(UINT_PTR, UCHAR);
		std::string readout32(UINT_PTR, UCHAR);
	}
}

#endif 




