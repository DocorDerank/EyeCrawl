// structs.cpp : Defines the entry point for the console application.
// 
// include if using:
// #include "stdafx.h"
#include <iostream>
#include "eyecrawl.h"
#include <conio.h>
#include <TlHelp32.h>
#include <Psapi.h>

int main(){
	HWND hWnd;
	HANDLE handle;
	unsigned long id = 0;
	hWnd = FindWindowA(NULL, "Roblox");
	GetWindowThreadProcessId(hWnd,&id);

	handle = OpenProcess(PROCESS_ALL_ACCESS, false, id);
	if (handle == INVALID_HANDLE_VALUE) {
		std::cout << "Could not find a program to open...\n\n";
	} else {
		EyeCrawl::open(handle);
    
    		UINT_PTR gettop = EyeCrawl::aslr(0x7F1F40);
    		UINT_PTR readproto = EyeCrawl::aslr(0x65A7E0);
    		UINT_PTR start;
    
		printf("readproto:\n\n");
    
		start = readproto;
		for (int i=0; i<140; i++){
			EyeCrawl::pinstruction x = EyeCrawl::disassemble(start);
			if (x->r32[0] == R_ESI){ // check if instruction uses ESI
				char spaces[40];
				spaces[0] = '\0';
				for (int j=lstrlenA(x->data); j<40; j++) strcat_s(spaces," ");
				
				// display the assembly code
				// and the offset from ESI register
				// which is a Proto value
				printf("%s%s// %i\n", x->data, spaces, x->offset);
			}
      			start += x->size; // move onto next instruction
			delete x;
		}

		printf("\n\nLua State - \n");
		
		int top, base;
		start = gettop;
		for (int i=0,j=0; i<5; i++){
			EyeCrawl::pinstruction x = EyeCrawl::disassemble(start);
      			// ignore the (register)=lua_state instruction
			if (x->r32[1] != R_EBP && x->offset > 0){
        			// first mov instruction is for lua state top
				if (j == 0) top = x->offset;
        			// second one subtracts lua state base
				if (j == 1) base = x->offset;
				j++;
			}
      			start += x->size; // move onto next instruction
			delete x;
		}

		printf("top: %i.\n",	top);
		printf("base: %i.\n",	base);

		printf("\n\n\n");
		system("PAUSE");
	}

    return 0;
}

