// -----------------------------------------------------------
//  ______                 ____
// |        \  /   ____   /    \ | ____   ____,           |
// |____     \/  /_____/ |       |/      /    | \       / |
// |         /  |        |       |      |     |  \  |  /  |
// |______  /    \_____/  \____/ |       \____/\  \/ \/   |
//
// -----------------------------------------------------------
// 
#include "stdafx.h"
#include "eyecrawl.h"
#include <TlHelp32.h>
#include <Psapi.h>
//
// Things to keep in mind with updating:
// 
// Any updates to the destination side, MAKE SURE
// it applies to the source side as well.
// Unless, the second operand requires a different
// algorithm, and VISE VERSA.
// 

// Private namespace definitions
// Plus it won't allow this in header
namespace EyeCrawl {
	HANDLE proc;
	UINT_PTR base_address;
	const char* _r8[8]	= {"al","cl","dl","bl","ah","ch","dh","bh"};
	const char* _r16[8] = {"ax","bx","cx","dx","sp","bp","si","di"};
	const char* _r32[8] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
	const char* _r64[8] = {"rax","rbx","rcx","rdx","rsp","rbp","rsi","rdi"}; // COMING SOON
	const char* _conds[16] = {"o","no","b","nb","e","ne","na","a","s","ns","p","np","l","nl","lng","g"};
}

void EyeCrawl::set(HANDLE handle) {
	proc = handle;
	HMODULE hMods[1024];
	unsigned long cbNeeded,mCurrent=0;
	if (EnumProcessModulesEx(handle,hMods,1024,&cbNeeded,LIST_MODULES_ALL)){
		for (int i=0; i<(cbNeeded/sizeof(HMODULE)); i++){
			MODULEINFO info;
			char szModPath[MAX_PATH];
			if (GetModuleFileNameExA(handle,hMods[i],szModPath,sizeof(szModPath)) && K32GetModuleInformation(handle,hMods[i],&info,cbNeeded)){
				if (mCurrent++==0) base_address = reinterpret_cast<UINT_PTR>(info.lpBaseOfDll);
			}
		}
	}
}

UINT_PTR EyeCrawl::aslr(UINT_PTR addr) {
	return (addr - 0x400000 + base_address);
}

UINT_PTR EyeCrawl::non_aslr(UINT_PTR addr) {
	return (addr + 0x400000 - base_address);
}

unsigned char EyeCrawl::readb(UINT_PTR addr) {
	if (DLL_MODE) return *(unsigned char*)addr;
	unsigned char buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,1,0);
	return buffer;
}

USHORT EyeCrawl::readus(UINT_PTR addr) {
	if (DLL_MODE) return *(USHORT*)addr;
	USHORT buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,2,0);
	return buffer;
}

int EyeCrawl::readi(UINT_PTR addr) {
	if (DLL_MODE) return *(int*)addr;
	int buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,4,0);
	return buffer;
}

UINT_PTR EyeCrawl::readui(UINT_PTR addr) {
	if (DLL_MODE) return *(int*)addr;
	UINT_PTR buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,4,0);
	return buffer;
}

EyeCrawl::instruction* EyeCrawl::disassemble(UINT_PTR addr) {
	instruction* x = new instruction();
	if (proc == INVALID_HANDLE_VALUE) return x; // return 0 size instruction (this is bad!!!!)

	unsigned char b=readb(addr), single_reg=0;

	// For single-byte instructions,
	// we will just use math to calculate
	// them here.
	// 
	// inc, dec, push, pop 
	if (b>=0x40 && b<0x48){
		strcpy_s(x->opcode, "inc");
		strcpy_s(x->data, "inc ");
		strcat_s(x->data, _r32[b-0x40]);
		x->r32[0] = (b-0x40);
		x->size++;
		set_d(x,r32);
		return x;
	} else if (b>=0x48 && b<0x50){
		strcpy_s(x->opcode, "dec");
		strcpy_s(x->data, "dec ");
		strcat_s(x->data, _r32[b-0x48]);
		x->r32[0] = (b-0x48);
		x->size++;
		set_d(x,r32);
		return x;
	} else if (b>=0x50 && b<0x58){
		strcpy_s(x->opcode, "push");
		strcpy_s(x->data, "push ");
		strcat_s(x->data, _r32[b-0x50]);
		x->r32[0] = (b-0x50);
		x->size++;
		set_d(x,r32);
		return x;
	} else if (b>=0x58 && b<0x60){
		strcpy_s(x->opcode, "pop");
		strcpy_s(x->data, "pop ");
		strcat_s(x->data, _r32[b-0x58]);
		x->r32[0] = (b-0x58);
		x->size++;
		set_d(x,r32);
		return x;
	}

	// identify the opcode
	switch (b){
		case 0x03:
			strcpy_s(x->opcode,"add");
			set_d(x,r16_32);
			set_s(x,r_m16_32);
			break;
		case 0x23:
			strcpy_s(x->opcode,"and"); // performs AND operation
			set_d(x,r16_32);	// AND r16, r/m16 (set destination)
			set_s(x,r_m16_32);	// AND r32, r/m32 (set source)
			break;
		case 0x24: // single-register instruction, just do imm8 value
			strcpy_s(x->opcode,"and al");
			single_reg=true;
			set_s(x,imm8);
			break;
		case 0x2B:
			strcpy_s(x->opcode,"sub");
			set_d(x,r16_32);
			set_s(x,r_m16_32);
			break;
		case 0x33:
			strcpy_s(x->opcode,"xor");
			set_d(x,r16_32);
			set_s(x,r_m16_32);
			break;
		case 0x38:
			strcpy_s(x->opcode,"cmp");
			set_d(x,r_m16_32);
			set_s(x,r8);
			break;
		case 0x3B:
			strcpy_s(x->opcode,"cmp");
			set_d(x,r16_32);
			set_s(x,r_m16_32);
			break;
		case 0x66:
			x->size++;
			switch (readb(addr+x->size)){
				case 0x90:
					strcpy_s(x->opcode,"xchg");
					strcpy_s(x->data,"xchg ax,ax");
					x->size++;
					return x;
				break;
			}
			break;
		case 0x68:
			strcpy_s(x->opcode,"push");
			set_d(x,imm32);
			break;
		case 0x6A:
			strcpy_s(x->opcode,"push");
			set_d(x,imm8);
			break;
		case 0x70:
			strcpy_s(x->opcode, "jo short"); // jmp short if overflow
			set_d(x,rel8);
			break;
		case 0x71:
			strcpy_s(x->opcode, "jno short"); // jmp short if not overflow
			set_d(x,rel8);
			break;
		case 0x72:
			strcpy_s(x->opcode, "jb short"); // jmp short if below
			set_d(x,rel8);
			break;
		case 0x73:
			strcpy_s(x->opcode, "jnb short"); // jmp short if above or equal / not below
			set_d(x,rel8);
			break;
		case 0x74:
			strcpy_s(x->opcode, "je short"); // jmp short if equal
			set_d(x,rel8);
			break;
		case 0x75:
			strcpy_s(x->opcode, "jne short"); // jmp short if not equal
			set_d(x,rel8);
			break;
		case 0x76:
			strcpy_s(x->opcode, "jbe short"); // jmp short if not above / below or equal
			set_d(x,rel8);
			break;
		case 0x77:
			strcpy_s(x->opcode, "ja short"); // jmp short if above
			set_d(x,rel8);
			break;
		case 0x78:
			strcpy_s(x->opcode, "js short"); // jmp short if sign
			set_d(x,rel8);
			break;
		case 0x79:
			strcpy_s(x->opcode, "jns short"); // jmp short if not sign
			set_d(x,rel8);
			break;
		case 0x7A:
			strcpy_s(x->opcode, "jp short"); // jmp short if parity
			set_d(x,rel8);
			break;
		case 0x7B:
			strcpy_s(x->opcode, "jnp short"); // jmp short if not parity
			set_d(x,rel8);
			break;
		case 0x7C:
			strcpy_s(x->opcode, "jl short"); // jmp short if less
			set_d(x,rel8);
			break;
		case 0x7D:
			strcpy_s(x->opcode, "jnl short"); // jmp short if not less
			set_d(x,rel8);
			break;
		case 0x7E:
			strcpy_s(x->opcode, "jng short"); // jmp short if not great
			set_d(x,rel8);
			break;
		case 0x7F:
			strcpy_s(x->opcode, "jg short"); // jmp short if greater
			set_d(x,rel8);
			break;
		case 0x80:
			switch (readb(addr+1)%40/8){
				case 0:
					strcpy_s(x->opcode,"add");
					break;
				case 1:
					strcpy_s(x->opcode,"or");
					break;
				case 2:
					strcpy_s(x->opcode,"adc");
					break;
				case 3:
					strcpy_s(x->opcode,"sbb");
					break;
				case 4:
					strcpy_s(x->opcode,"and");
					break;
				case 5:
					strcpy_s(x->opcode,"sub");
					break;
				case 6:
					strcpy_s(x->opcode,"xor");
					break;
				case 7:
					strcpy_s(x->opcode,"cmp");
				break;
			}
			if (readb(addr+1) >= 0xC0){
				strcat_s(x->opcode," byte ptr");
				set_d(x,r8);
				set_s(x,imm8);
			} else {
				strcat_s(x->opcode," dword ptr");
				set_d(x,r_m16_32);
				set_s(x,imm8);
			}
			break;
		case 0x81:
			switch (readb(addr+1)%0x40/8){
				case 0:
					strcpy_s(x->opcode,"add dword ptr");
					set_d(x,r_m16_32);
					set_s(x,imm32);
					break;
				case 1:
					strcpy_s(x->opcode,"or dword ptr");
					set_d(x,r_m16_32);
					set_s(x,imm32);
					break;
				case 2:
					strcpy_s(x->opcode,"adc dword ptr");
					set_d(x,r_m16_32);
					set_s(x,imm32);
					break;
				case 3:
					strcpy_s(x->opcode,"sbb dword ptr");
					set_d(x,r_m16_32);
					set_s(x,imm32);
					break;
				case 4:
					strcpy_s(x->opcode,"and dword ptr");
					set_d(x,r_m16_32);
					set_s(x,imm32);
					break;
				case 5:
					strcpy_s(x->opcode,"sub dword ptr");
					set_d(x,r_m16_32);
					set_s(x,imm32);
					break;
				case 6:
					strcpy_s(x->opcode,"xor dword ptr");
					set_d(x,r_m16_32);
					set_s(x,imm32);
					break;
				case 7:
					strcpy_s(x->opcode,"cmp dword ptr");
					set_d(x,r_m16_32);
					set_s(x,imm32);
					break;
			}
			break;
		case 0x82:
			switch (readb(addr+1)%0x40/8){
				case 0:
					strcpy_s(x->opcode,"add byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 1:
					strcpy_s(x->opcode,"or byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 2:
					strcpy_s(x->opcode,"adc byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 3:
					strcpy_s(x->opcode,"sbb byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 4:
					strcpy_s(x->opcode,"and byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 5:
					strcpy_s(x->opcode,"sub byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 6:
					strcpy_s(x->opcode,"xor byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 7:
					strcpy_s(x->opcode,"cmp byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
			}
			break;
		case 0x83:
			switch (readb(addr+1)%0x40/8){
				case 0:
					strcpy_s(x->opcode,"add");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 1:
					strcpy_s(x->opcode,"or");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 2:
					strcpy_s(x->opcode,"adc");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 3:
					strcpy_s(x->opcode,"sbb");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 4:
					strcpy_s(x->opcode,"and");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 5:
					strcpy_s(x->opcode,"sub");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 6:
					strcpy_s(x->opcode,"xor");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 7:
					strcpy_s(x->opcode,"cmp dword ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
			}
			break;
		case 0x85:
			strcpy_s(x->opcode,"test");
			set_d(x,r_m16_32);
			set_s(x,r16_32);
			break;
		case 0x88:
			strcpy_s(x->opcode,"mov");
			set_d(x,r_m16_32);
			set_s(x,r8);
			break;
		case 0x89:
			strcpy_s(x->opcode,"mov");
			set_d(x,r_m16_32);
			set_s(x,r16_32);
			break;
		case 0x8A:
			strcpy_s(x->opcode,"mov");
			set_d(x,r8);
			set_s(x,r_m16_32);
			break;
		case 0x8B:
			strcpy_s(x->opcode,"mov");
			set_d(x,r16_32);
			set_s(x,r_m16_32);
			break;
		case 0x8D:
			strcpy_s(x->opcode,"lea");
			set_d(x,r16_32);
			set_s(x,r_m16_32);
			break;
		case 0xA1:
			strcpy_s(x->opcode, "mov eax");
			single_reg=true;
			set_s(x,imm32);
			break;
		case 0xA2:{
			strcpy_s(x->opcode, "mov");
			strcpy_s(x->data, "mov dword:");
			char c[16];
			sprintf_s(c,"%08X",readui(addr+1));
			strcat_s(x->data, c);
			strcat_s(x->data, ",al");
			x->size=5;
			return x;
		} break;
		case 0xA3:{
			strcpy_s(x->opcode, "mov");
			strcpy_s(x->data, "mov dword:");
			char c[16];
			sprintf_s(c,"%08X",readui(addr+1));
			strcat_s(x->data, c);
			strcat_s(x->data, ",eax");
			x->size=5;
			return x;
		} break;
		case 0xB8:
			strcpy_s(x->opcode, "mov eax");
			single_reg=true;
			set_s(x,imm32);
			break;
		case 0xB9:
			strcpy_s(x->opcode, "mov ecx");
			single_reg=true;
			set_s(x,imm32);
			break;
		case 0xBA:
			strcpy_s(x->opcode, "mov edx");
			single_reg=true;
			set_s(x,imm32);
			break;
		case 0xBB:
			strcpy_s(x->opcode, "mov ebx");
			single_reg=true;
			set_s(x,imm32);
			break;
		case 0xBC:
			strcpy_s(x->opcode, "mov esp");
			single_reg=true;
			set_s(x,imm32);
			break;
		case 0xBD:
			strcpy_s(x->opcode, "mov ebp");
			single_reg=true;
			set_s(x,imm32);
			break;
		case 0xBE:
			strcpy_s(x->opcode, "mov esi");
			single_reg=true;
			set_s(x,imm32);
			break;
		case 0xBF:
			strcpy_s(x->opcode, "mov edi");
			single_reg=true;
			set_s(x,imm32);
			break;
		case 0xC0:
			switch (readb(addr+1)%0x40/8){
				case 0:
					strcpy_s(x->opcode,"rol byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 1:
					strcpy_s(x->opcode,"ror byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 2:
					strcpy_s(x->opcode,"rcl byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 3:
					strcpy_s(x->opcode,"rcr byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 4:
					strcpy_s(x->opcode,"shl byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 5:
					strcpy_s(x->opcode,"shr byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				// CASE 6 NOT COVERED BY INTEL DOCUMENTATION
				case 7:
					strcpy_s(x->opcode,"sar byte ptr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
			}
			break;
		case 0xC1:
			switch (readb(addr+1)%0x40/8){
				case 0:
					strcpy_s(x->opcode,"rol");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 1:
					strcpy_s(x->opcode,"ror");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 2:
					strcpy_s(x->opcode,"rcl");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 3:
					strcpy_s(x->opcode,"rcr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 4:
					strcpy_s(x->opcode,"shl");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				case 5:
					strcpy_s(x->opcode,"shr");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
				// CASE 6 NOT COVERED BY INTEL DOCUMENTATION
				case 7:
					strcpy_s(x->opcode,"sar");
					set_d(x,r_m16_32);
					set_s(x,imm8);
					break;
			}
			break;
		case 0xC2:
			strcpy_s(x->opcode, "ret");
			set_d(x,imm16);
			break;
		case 0xC3:
			strcpy_s(x->opcode, "retn");
			break;
		case 0xC6:
			if (readb(addr+1)%0x40<8){
				strcpy_s(x->opcode, "mov byte ptr");
				set_d(x, r_m16_32);
				set_s(x, imm8);
				break;
			}
			break;
		case 0xC7:
			if (readb(addr+1)%0x40<8){
				strcpy_s(x->opcode, "mov dword ptr");
				set_d(x, r_m16_32);
				set_s(x, imm32);
				break;
			}
			break;
		case 0xCC:
			strcpy_s(x->opcode,"align");
			break;
		case 0xE8:
			strcpy_s(x->opcode,"call");
			set_d(x,rel32);
			break;
		case 0xE9:
			strcpy_s(x->opcode,"jmp");
			set_d(x,rel32);
			break;
		case 0xEB:
			strcpy_s(x->opcode,"jmp short");
			set_d(x,rel8);
			break;

		case 0x0F:{
			x->size++;
			unsigned char b=readb(addr+x->size);
			if (b>=0x40 && b<0x50){
				strcpy_s(x->opcode, "cmov");
				strcat_s(x->opcode, _conds[b-0x40]);
				set_d(x,r16_32);
				set_s(x,r_m16_32);
				break;
			} else if (b>=0x80 && b<0x90){
				strcpy_s(x->opcode, "j");
				strcat_s(x->opcode, _conds[b-0x80]);
				set_d(x,rel32);
				break;
			} else {
				switch (b) {
					case 0x1F:
						strcpy_s(x->opcode, "nop dword ptr");
						set_d(x,r_m16_32);
						break;
					
					case 0xB6:
						strcpy_s(x->opcode, "movzx");
						if (readb(addr+x->size+1) >= 0xC0){
							set_d(x,r16_32);
							set_s(x,r8);
						} else {
							set_d(x,r16_32);
							set_s(x,r_m16_32);
						}
					break;

					case 0xBA:
						// "0F BA '/7' ib"
						// 0x20-0x30-0x40, 0x60-0x70-0x80, 0xA0-0xB0-0xC0
						// has two modes (bt/btr)
						if ((readb(addr+x->size+1) / 0x20) % 2!=0){
							unsigned char m=((readb(addr+x->size+1) % 0x20) / 8);
							switch (m) {
								case 0:
									strcpy_s(x->opcode, "bt");
									set_d(x,r_m16_32);
									set_s(x,imm8);
									break;
								case 1:
									strcpy_s(x->opcode, "bts");
									set_d(x,r_m16_32);
									set_s(x,imm8);
									break;
								case 2:
									strcpy_s(x->opcode, "btr");
									set_d(x,r_m16_32);
									set_s(x,imm8);
									break;
								case 3:
									strcpy_s(x->opcode, "btc");
									set_d(x,r_m16_32);
									set_s(x,imm8);
								break;
							}
						}
					break;
					case 0xBB:
						strcpy_s(x->opcode, "btc");
						set_d(x,r_m16_32);	// BTC r/m16, r16
						set_s(x,r16_32);	// BTC r/m32, r32
					break;
				}
			}
		} break;

		case 0xF0:
			x->size++;
			switch (readb(addr+x->size)){
				case 0xFF:
					x->size++;
					switch (readb(addr+x->size)){
						case 0x05:
							strcpy_s(x->opcode, "lock inc dword:");
							set_d(x,imm32);
						break;
					}
				break;
			}
		break;

		case 0xF7:
			x->size++;
			if (readb(addr+x->size) % 0x40 < 8){
				strcpy_s(x->opcode, "test");
				set_d(x,r_m16_32);
				set_s(x,imm16); // short value test
			}
			if (readb(addr+x->size) >= 0xD0) {
				switch ((readb(addr+x->size)-0xD0)/8){
					case 0:
						strcpy_s(x->opcode, "not");
						set_d(x,r32);
						break;
					case 1:
						strcpy_s(x->opcode, "neg");
						set_d(x,r32);
						break;
					case 2:
						strcpy_s(x->opcode, "mul");
						set_d(x,r32);
						break;
					case 3:
						strcpy_s(x->opcode, "imul");
						set_d(x,r32);
						break;
					case 4:
						strcpy_s(x->opcode, "div");
						set_d(x,r32);
						break;
					case 5:
						strcpy_s(x->opcode, "idiv");
						set_d(x,r32);
					break;
				}
			}
		break;

		case 0xFF:
			switch (readb(addr+1)%0x40/8){
				case 0:
					strcpy_s(x->opcode,"inc dword ptr");
					set_d(x,r_m16_32);
					break;
				case 1:
					strcpy_s(x->opcode,"dec dword ptr");
					set_d(x,r_m16_32);
					break;
				case 2:
					strcpy_s(x->opcode,"call dword ptr");
					set_d(x,r_m16_32);
					break;
				case 3:
					strcpy_s(x->opcode,"call dword ptr");
					set_d(x,r_m16_32);
					break;
				case 4:
					strcpy_s(x->opcode,"jmp dword ptr");
					set_d(x,r_m16_32);
					break;
				case 5:
					strcpy_s(x->opcode,"jmp far dword ptr");
					set_d(x,r_m16_32);
					break;
				case 6:
					strcpy_s(x->opcode,"push dword ptr");
					set_d(x,r_m16_32);
				break;
				// CASE 7 NOT COVERED BY INTEL DOCUMENTATION
			}
		break;

		default:
			strcpy_s(x->opcode,"?");
			strcpy_s(x->data,"?");
			x->size++;
			return x;
		break;
	}

	x->size++;
	unsigned char c,mode20,mode40,i,j,oldj=0,skip=0;
	strcpy_s(x->data, x->opcode);
	if (!single_reg) strcat_s(x->data, " ");

	char cnv[16]; // for future values we have to convert to string
	char second_op[4];

	// Used for furthering the instruction
	// by updating the values corresponding
	// to the next byte
	// 
	auto update=[&c,&addr,&x,&mode20,&mode40,&i,&j](){
		c=readb(addr+x->size);
		mode20=c/32;
		mode40=c/64;
		i=c%8;
		j=c%64/8;
	};

	// *calibrate and then extend size
	auto extend=[&c,&addr,&x,update](){
		update();
		x->size++;
	};

	// Quick functions to help translate
	// the asm to readable text
	//
	auto w_offset8=[&x,&cnv,&addr](){
		unsigned char v=readb(addr+x->size);
		x->offset = v;
		if (v <= 0x7F){
			sprintf_s(cnv,"%02X",v);
			strcat_s(x->data, "+");
			strcat_s(x->data, cnv);
		} else {
			sprintf_s(cnv,"%02X",(UCHAR_MAX-v+1));
			strcat_s(x->data, "-");
			strcat_s(x->data, cnv);
		}
		x->size += 1;
	};

	auto w_offset16=[&x,&cnv,&addr](){
		USHORT v=readus(addr+x->size);
		x->offset = v;
		if (v <= 0x7FFF){
			sprintf_s(cnv,"%04X",v);
			strcat_s(x->data, "+");
			strcat_s(x->data, cnv);
		} else {
			sprintf_s(cnv,"%04X",(USHRT_MAX-v+1));
			strcat_s(x->data, "-");
			strcat_s(x->data, cnv);
		}
		x->size += sizeof(USHORT);
	};

	auto w_offset32=[&x,&cnv,&addr](){
		UINT_PTR v=readui(addr+x->size);
		x->offset = v;
		if (v <= 0x7FFFFFFF){
			sprintf_s(cnv,"%08X",v);
			strcat_s(x->data, "+");
			strcat_s(x->data, cnv);
		} else {
			sprintf_s(cnv,"%08X",(UINT32_MAX-v+1));
			strcat_s(x->data, "-");
			strcat_s(x->data, cnv);
		}
		x->size += sizeof(UINT_PTR);
	};

	auto w_mult32=[&x,&mode40](){
		if (mode40 != 0) {
			int mul=(mode40==1)?2:(mode40==2)?4:(mode40==3)?8:0;
			char s_mul[2];
			sprintf_s(s_mul,"%i",mul);
			strcat_s(x->data, "*");
			strcat_s(x->data, s_mul);
		}
	};

	update();

	// FIRST OPERAND
	switch (x->dest) {
		case _m::none: break;

		// Check 8bit value on the next byte
		case _m::imm8:{
			unsigned char v = readb(addr+x->size);
			x->v8 = v;
			sprintf_s(cnv,"%02X",v);
			strcat_s(x->data,cnv);
			x->size += 1;
		} break;
		// Check 16bit value on the next 2 bytes
		case _m::imm16:{
			USHORT v = readus(addr+x->size);
			x->v16 = v;
			sprintf_s(cnv,"%04X",v);
			strcat_s(x->data,cnv);
			x->size += sizeof(USHORT);
		} break;
		// Check 32bit value on the next 4 bytes
		case _m::imm32:{
			UINT_PTR v = readui(addr+x->size);
			x->v32 = v;
			sprintf_s(cnv,"%08X",v);
			strcat_s(x->data,cnv);
			x->size += sizeof(UINT_PTR);
		} break;

		case _m::rel8:{
			unsigned char v = ((addr+x->size+1) + readb(addr+x->size));
			x->v8 = v;
			sprintf_s(cnv,"%02X",v);
			strcat_s(x->data,cnv);
			x->size += 1;
		} break;
		case _m::rel16:{
			USHORT v = (addr+x->size+2) + readus(addr+x->size);
			x->v16 = v;
			sprintf_s(cnv,"%04X",v);
			strcat_s(x->data,cnv);
			x->size += sizeof(USHORT);
		} break;
		case _m::rel32:{
			UINT_PTR v = (addr+x->size+4) + readui(addr+x->size);
			x->v32 = v;
			sprintf_s(cnv,"%08X",v);
			strcat_s(x->data,cnv);
			x->size += sizeof(UINT_PTR);
		} break;

		case _m::r8:
			strcat_s(x->data,_r8[j]); // goes by 8ths
		break;
		case _m::r16:
			strcat_s(x->data,_r16[j]); // have not gotten here yet
		break;
		case _m::r32:
			strcat_s(x->data,_r32[j]);
		break;

		case _m::r16_32:
			x->r32[0] = j;
			switch (mode40){
				case 0: // 0x00 through 0x3F
					switch (i){
						case 0x4:
							strcat_s(x->data,_r32[j]);
							break;
						case 0x5:
							strcat_s(x->data,_r32[(c-0x5)/8]);
							x->size++;
							x->src = _m::imm32;
							break;
						default:
							strcat_s(x->data,_r32[j]);
							break;
					}
				break;
				default: // 0x40-0xFF
					strcat_s(x->data,_r32[j]);
				break;
			}
		break;

		case _m::r_m16_32:{
			// This is done because a previous byte could
			// represent the second operand, which
			// we need to know, if it is a register
			unsigned char	can_solve_second_r8op = 
									(x->src==_m::r8),
							can_solve_second_r16op = 
									(x->src==_m::r16),
							can_solve_second_r32op =
									(x->src==_m::r32 ||
									x->src==_m::r16_32);
			// For any case, we need to skip the second
			// operand check
			skip = (can_solve_second_r8op ||
					can_solve_second_r16op ||
					can_solve_second_r32op);

			extend();
			x->r32[0] = i;
			switch (mode40) {
				case 3: // 0xC0 through 0xFF
					strcat_s(x->data, _r32[i]);
					break;
				case 2: // 0x80 through 0xBF
					strcat_s(x->data, "[");
					oldj = j;
					switch(i){
						case 0x4:
							extend();
							x->r32[0] = i;
							strcat_s(x->data, _r32[i]);
							if (mode20%2!=1 || c%0x20>=16){ 
								strcat_s(x->data, "+");
								strcat_s(x->data, _r32[j]);
								w_mult32();
							} else if (c%0x20>=8) {
								strcat_s(x->data, "+");
								strcat_s(x->data, _r32[j]);
							}
							break;
						default:
							strcat_s(x->data, _r32[i]);
							break;
					}
					w_offset32();
					strcat_s(x->data, "]");
					break;
				case 1: // 0x40 through 0x80
					strcat_s(x->data, "[");
					oldj = j;
					switch(i){
						case 0x4:
							extend();
							x->r32[0] = i;
							strcat_s(x->data, _r32[i]);
							if (mode20%2!=1 || c%0x20>=16){ 
								strcat_s(x->data, "+");
								strcat_s(x->data, _r32[j]);
								w_mult32();
							} else if (c%0x20>=8) {
								strcat_s(x->data, "+");
								strcat_s(x->data, _r32[j]);
							}
							break;
						default:
							strcat_s(x->data, _r32[i]);
							break;
					}
					w_offset8();
					strcat_s(x->data, "]");
					break;
				case 0: // 0x00 through 0x40
					strcat_s(x->data, "[");
					oldj = j;
					switch(i){
						case 0x4:
							extend();
							x->r32[0] = i;
							switch(i){
								case 0x5:
									if ((mode20+1)%2==0){
										sprintf_s(cnv,"%08X",readui(addr+x->size));
										strcat_s(x->data, cnv);
										x->size += sizeof(UINT_PTR);
									} else {
										strcat_s(x->data, _r32[j]);
										w_mult32();
										w_offset32();
									}
								break;
								default:
									strcat_s(x->data, _r32[i]);
									if (mode20%2!=1 || c%0x20>=16){ 
										strcat_s(x->data, "+");
										strcat_s(x->data, _r32[j]);
										w_mult32();
									} else if (c%0x20>=8) {
										strcat_s(x->data, "+");
										strcat_s(x->data, _r32[j]);
										w_mult32();
									}
								break;
							}
							break;
						case 0x5:
							sprintf_s(cnv,"%08X",readui(addr+x->size));
							strcat_s(x->data, cnv);
							x->size += sizeof(UINT_PTR);
							break;
						default:
							strcat_s(x->data, _r32[i]);
							break;
					}
					strcat_s(x->data, "]");
					break;
				break;
			}
			if (skip){ // We are solving for the second operand
				if (can_solve_second_r8op){	x->r8[1]=oldj; strcpy_s(second_op,_r8[oldj]); }
				if (can_solve_second_r16op){ x->r16[1]=oldj; strcpy_s(second_op,_r16[oldj]); }
				if (can_solve_second_r32op){ x->r32[1]=oldj; strcpy_s(second_op,_r32[oldj]); }
				strcat_s(x->data, ",");
				strcat_s(x->data, second_op);
			}
		} break;
	}

	// SECOND OPERAND, if not already configured
	if (!skip && x->src != _m::none){
		strcat_s(x->data,",");
		
		switch (x->src) {
			// Check 8bit value on the next byte
			case _m::imm8:{
				unsigned char v = readb(addr+x->size);
				x->v8 = v;
				sprintf_s(cnv,"%02X",v);
				strcat_s(x->data,cnv);
				x->size += 1;
			} break;
			// Check 16bit value on the next 2 bytes
			case _m::imm16:{
				USHORT v = readus(addr+x->size);
				x->v16 = v;
				sprintf_s(cnv,"%04X",v);
				strcat_s(x->data,cnv);
				x->size += sizeof(USHORT);
			} break;
			// Check 32bit value on the next 4 bytes
			case _m::imm32:{
				UINT_PTR v = readui(addr+x->size);
				x->v32 = v;
				sprintf_s(cnv,"%08X",v);
				strcat_s(x->data,cnv);
				x->size += sizeof(UINT_PTR);
			} break;

			case _m::rel8:{
				unsigned char v = ((addr+x->size+1) + readb(addr+x->size));
				x->v8 = v;
				sprintf_s(cnv,"%02X",v);
				strcat_s(x->data,cnv);
				x->size += 1;
			} break;
			case _m::rel16:{
				USHORT v = (addr+x->size+2) + readus(addr+x->size);
				x->v16 = v;
				sprintf_s(cnv,"%04X",v);
				strcat_s(x->data,cnv);
				x->size += sizeof(USHORT);
			} break;
			case _m::rel32:{
				UINT_PTR v = (addr+x->size+4) + readui(addr+x->size);
				x->v32 = v;
				sprintf_s(cnv,"%08X",v);
				strcat_s(x->data,cnv);
				x->size += sizeof(UINT_PTR);
			} break;

			case _m::r8:
				strcat_s(x->data,_r8[i]);
			break;
			case _m::r16:
				strcat_s(x->data,_r16[i]);
			break;
			case _m::r32:
				strcat_s(x->data,_r32[i]);
			break;

			case _m::r16_32:
				x->r32[1] = j;
				switch (mode40){
					case 0: // 0x00 through 0x3F
						switch (i){
							case 0x4:
								strcat_s(x->data,_r32[j]);
								break;
							case 0x5:
								strcat_s(x->data,_r32[(c-0x5)/8]);
								x->src = _m::imm32;
								break;
							default:
								strcat_s(x->data,_r32[j]);
								break;
						}
					break;
					default: // 0x40-0xFF
						strcat_s(x->data,_r32[j]);
					break;
				}
			break;

			case _m::r_m16_32:
				extend();
				x->r32[1] = i;
				switch (mode40){
					case 3: // 0xC0 through 0xFF		[op] eax,[eax]
						strcat_s(x->data,_r32[i]);
					break;
					case 2: // 0x80 through 0xBF		[op] eax,[eax+eax*?+????????]
						strcat_s(x->data, "[");
						switch(i){
							case 0x4:
								extend();
								x->r32[1] = i;
								strcat_s(x->data, _r32[i]);
								// 0x60 = [op] eax,[eax+00000000]
								// 0xA0 = [op] eax,[eax+00000000]
								// but, 0x80 = [op] eax,[eax+eax*4+00000000]
								//
								strcat_s(x->data, "+");
								strcat_s(x->data, _r32[j]);
								w_mult32();
								break;
							default:
								strcat_s(x->data, _r32[i]);
								break;
						}
						w_offset32();
						strcat_s(x->data, "]");
					break;
					case 1: // 0x40 through 0x7F		[op] eax,[eax+eax*?+??]
						strcat_s(x->data, "[");
						switch(i){
							case 0x4:
								extend();
								x->r32[1] = i;
								strcat_s(x->data, _r32[i]);
								if (!(mode20%2!=0 && c%0x20<8)){
									strcat_s(x->data, "+");
									strcat_s(x->data, _r32[j]);
									w_mult32();
								}
							break;
							default:
								strcat_s(x->data, _r32[i]);
							break;
						}
						w_offset8();
						strcat_s(x->data, "]");
					break;
					case 0:
						strcat_s(x->data, "[");
						switch(i){
							case 0x4:
								extend();
								x->r32[1] = i;
								switch(i){
									case 0x5:
										if (mode20%2!=1){
											strcat_s(x->data, _r32[j]);
											w_mult32();
											w_offset32();
										} else {
											sprintf_s(cnv,"%08X",readui(addr+x->size));
											strcat_s(x->data, cnv);
											x->size += sizeof(UINT_PTR);
										}
									break;
									default:
										strcat_s(x->data, _r32[i]);
										if (mode20%2!=1){
											strcat_s(x->data, "+");
											strcat_s(x->data, _r32[j]);
											w_mult32();
										} else if (c%0x20>=8) {
											strcat_s(x->data, "+");
											strcat_s(x->data, _r32[j]);
											w_mult32();
										}
									break;
								}
							break;
							default:
								strcat_s(x->data, _r32[i]);
							break;
						}
						strcat_s(x->data, "]");
					break;
				}
			break;
		}
	}

	return x;
}

std::string replaceex(std::string str, const char* replace, const char* mask, const char* newstr) {
	std::string x;
	int size=lstrlenA(mask);
	for (int i=0; i<str.length(); i++){
		bool matched=(i<(str.length()-size));
		if (matched) // dont check past the string size
			for (int j=0; j<size; j++)
				if (mask[j]=='.' && str[i+j]!=replace[j])
					matched=false;
		if (matched){
			i += (size-1);
			x += newstr;
		} else {
			x += str[i];
		}
	}
	return x;
}

bool strfind(const char* A, const char* B) {
	bool found = true;
	for (int i=0; i < (lstrlenA(A) - lstrlenA(B)); i++){
		found = true;
		for (int j=0; j < lstrlenA(B); j++)
			if (A[i+j] != B[j])
				found = false;
		if (found) return found;
	}
	return false;
}

std::string EyeCrawl::disassemble(UINT_PTR addr, int count, info_mode extra_info) {
	std::string str = "";
	if (proc == INVALID_HANDLE_VALUE) return str;

	for (int n=0,s=0; n<count; n++) {
		EyeCrawl::pinstruction i = EyeCrawl::disassemble(addr+s);
		s += i->size;
		str += i->data;
		if (extra_info == show_offsets || extra_info == show_ioffsets){
			if (i->offset != 0) {
				char spaces[44];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces, " ");

				char c[4];
				if (extra_info == show_offsets)
					sprintf_s(c,"%02X",(unsigned char)i->offset);
				else if (extra_info == show_ioffsets)
					sprintf_s(c,"%i",(unsigned char)i->offset);
				str += spaces;
				str += " // ";
				str += c;
			}
		} else if (extra_info == show_int32){
			char spaces[44];
			spaces[0] = '\0';
			for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces, " ");

			char c[16];
			sprintf_s(c,"%i",i->v32);
			str += spaces;
			str += " // ";
			str += c;
		} else if (extra_info == show_args){
			if (strfind(i->data, "ebp+")){
				char spaces[44],c[8];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces," ");

				sprintf_s(c,"arg_%i",(unsigned char)((i->offset-0x8)/0x4));
				str = replaceex(str,"ebp+??","....xx",c);
				str += spaces;
				str += " // ";
				str += c;
			}
		} else if (extra_info == show_vars){
			if (strfind(i->data, "ebp-")){
				char spaces[44],c[8];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces," ");
				
				sprintf_s(c,"var_%i",(unsigned char)((UCHAR_MAX-i->offset-1)/0x4));
				str = replaceex(str,"ebp-??","....xx",c);
				str += spaces;
				str += " // ";
				str += c;
			}
		} else if (extra_info == show_args_and_vars){
			bool found_var = strfind(i->data, "ebp-");
			bool found_arg = strfind(i->data, "ebp+");
			if (found_var || found_arg){
				char spaces[44],c[8];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces," ");
				
				if (found_var){
					sprintf_s(c,"var_%i",(unsigned char)((UCHAR_MAX-i->offset-1)/0x4));
					str = replaceex(str,"ebp-??","....xx",c);
				} else if (found_arg){
					sprintf_s(c,"arg_%i",(unsigned char)((i->offset-0x8)/0x4));
					str = replaceex(str,"ebp+??","....xx",c);
				}

				str += spaces;
				str += " // ";
				str += c;
			}
		} else if (extra_info == show_non_aslr){
			if (strfind(i->data, "call") ||
				strfind(i->data, "jmp")){
				char spaces[44],c[16];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces," ");

				sprintf_s(c,"%08X",non_aslr(i->v32));
				str += spaces;
				str += " // ";
				str += c;
			}
		}
		str += "\n";
		delete i;
	}
	return str;
}

