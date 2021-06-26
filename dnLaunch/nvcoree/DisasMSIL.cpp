//   
//    Copyright (c) 2008 Daniel Pistelli.
// 

#include <Windows.h>
#include "DisasMSIL.h"

static DWORD HIDWORD(QWORD Q)
{
	QWORD qwBuf = Q >> 32;

	return (DWORD) qwBuf;
}

static DWORD LODWORD(QWORD Q)
{
	return (DWORD) Q;
}

BOOL GetSingleMSILInstr(BYTE *pMemory, 
						UINT MemorySize, 
						DISASMSIL_OFFSET CodeBase,
						ILOPCODE_STRUCT *ilop)
{
	BYTE *pCurInstr = (BYTE *) pMemory;
	DISASMSIL_OFFSET Base = CodeBase;

	//
	// This macro makes a validity check on the requested space
	//

#define VALIDATE(p, size)										\
	{															\
		UINT remsize = MemorySize - (UINT ) (((ULONG_PTR) p) -	\
			((ULONG_PTR) pMemory));								\
		if (remsize < size) return FALSE;						\
	}

	//
	// This little macro makes a validity check
	// on a request from the disassembler
	// when the request can't be satisfied, 
	// the function returns FALSE
	//

#define GET(p, var, type)											\
	{																\
		UINT typesize = sizeof (type);								\
		UINT remsize = MemorySize - (UINT) (((ULONG_PTR) p) -		\
			((ULONG_PTR) pMemory));									\
		if (typesize > remsize) return FALSE;						\
		var = *((type *) p);										\
	}

	//
	// This macro adds an instruction to the
	// current mnemonic string
	//
	
#define ADDI(i)																						\
	{																								\
		if (ilop->Mnemonic[0] == 0)																	\
			sprintf_s(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s", i);							\
		else																						\
			sprintf_s(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s %s", ilop->Mnemonic, i);			\
	}

	//
	// This macro adds a number to the
	// current mnemonic string
	//

#define NUMBER_TYPE_TOKEN						0
#define NUMBER_TYPE_SMALL_BRANCH				1
#define NUMBER_TYPE_BRANCH						2
#define NUMBER_TYPE_BYTE						3
#define NUMBER_TYPE_WORD						4
#define NUMBER_TYPE_DWORD						5
#define NUMBER_TYPE_QWORD						6
#define NUMBER_TYPE_CHAR						7
#define NUMBER_TYPE_SHORT						8
#define NUMBER_TYPE_INT							9
#define NUMBER_TYPE_INT64						10
#define NUMBER_TYPE_UCHAR						11
#define NUMBER_TYPE_USHORT						12
#define NUMBER_TYPE_UINT						13
// #define NUMBER_TYPE_UINT64						14
#define NUMBER_TYPE_FLOAT						15
#define NUMBER_TYPE_DOUBLE						16

#define ADDN(n,nt)				{																			\
		char szNumber[100];																					\
		switch (nt)																							\
		{																									\
		case NUMBER_TYPE_TOKEN: sprintf_s(szNumber, 100, "0x%08X", (DWORD) n); break;						\
		case NUMBER_TYPE_SMALL_BRANCH:																		\
			if (((BYTE) n) <= 127)																			\
				sprintf_s(szNumber, 100, "0x%08X", (DWORD) (Base + 2) + n);									\
			else																							\
				sprintf_s(szNumber, 100, "0x%08X", (DWORD) Base - (0 - (char) n));							\
			break;																							\
		case NUMBER_TYPE_BRANCH:																			\
			if (((DWORD) n) <= 0x7FFFFFFF)																	\
				sprintf_s(szNumber, 100, "0x%08X", (DWORD) (Base + 5) + n);									\
			else																							\
				sprintf_s(szNumber, 100, "0x%08X", (DWORD) Base - (0 - (int) n));							\
			break;																							\
		case NUMBER_TYPE_BYTE: sprintf_s(szNumber, 100, "0x%02X", (BYTE) n); break;							\
		case NUMBER_TYPE_WORD: sprintf_s(szNumber, 100, "0x%04X", (WORD) n); break;							\
		case NUMBER_TYPE_DWORD: sprintf_s(szNumber, 100, "0x%08X", (DWORD) n); break;						\
		case NUMBER_TYPE_QWORD: sprintf_s(szNumber, 100, "0x%08X%08X",										\
			HIDWORD(n), LODWORD(n)); break;																	\
		case NUMBER_TYPE_CHAR:	sprintf_s(szNumber, 100, "%d", (int) (CHAR) n); break;						\
		case NUMBER_TYPE_SHORT:	sprintf_s(szNumber, 100, "%hd", (short) n); break;							\
		case NUMBER_TYPE_INT: sprintf_s(szNumber, 100, "%d", (int) n); break;								\
		case NUMBER_TYPE_INT64: sprintf_s(szNumber, 100, "%I64d", (QWORD) n); break;						\
		case NUMBER_TYPE_UCHAR: sprintf_s(szNumber, 100, "%hu", (unsigned short) n); break;					\
		case NUMBER_TYPE_USHORT:	sprintf_s(szNumber, 100, "%hu", (short) n); break;						\
		case NUMBER_TYPE_UINT: sprintf_s(szNumber, 100, "%u", (int) n); break;								\
		case NUMBER_TYPE_FLOAT: sprintf_s(szNumber, 100, "%f", (float) n); break;							\
		case NUMBER_TYPE_DOUBLE: sprintf_s(szNumber, 100, "%Lf", (double) n); break;						\
		}																									\
		if (ilop->Mnemonic[0] == 0)																			\
			sprintf_s(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s", szNumber);								\
		else																								\
			sprintf_s(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s %s", ilop->Mnemonic, szNumber);			\
	}

	//
	// This macro adds an instruction and a token to the
	// current mnemonic string
	//

#define ADDIT(i, t)																						\
	{																									\
		if (ilop->Mnemonic[0] == 0)																		\
			sprintf_s(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s 0x%08X", i, t);						\
		else																							\
			sprintf_s(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s %s 0x%08X", ilop->Mnemonic, i, t);	\
	}

	//
	

	if (MemorySize == 0) return FALSE;

	ilop->Offset = Base;
	ilop->Mnemonic[0] = 0;

	//
	// Check if it's a one-byte instr
	// (in that case don't check for prefix)
	//

	UINT CurInstr;
	DWORD Token;

	BYTE bBuf = 0;
	WORD wBuf = 0;
	DWORD dwBuf = 0;
	QWORD qwBuf = 0;

	GET(pCurInstr, CurInstr, BYTE);

	if (CurInstr >= 0x00 && CurInstr <= 0xE0)
		goto getinstr;

	//
	// check for prefixes
	//

	UINT Prefix;

	GET(pCurInstr, Prefix, WORD);

	switch (Prefix)
	{
		
	case ILOPCODE_CONSTRAINED_:
		{
			GET(pCurInstr + 2, Token, DWORD);
			pCurInstr += 6;
			ADDIT("costrained", Token);
			break;
		}

	case ILOPCODE_UNALIGNED_:
		{
			GET(pCurInstr + 2, bBuf, BYTE);
			pCurInstr += 3;
			ADDI("unaligned");
			ADDN(bBuf, NUMBER_TYPE_UCHAR);
			break;
		}

	case ILOPCODE_NO_:
		{
			GET(pCurInstr + 2, bBuf, BYTE);
			pCurInstr += 3;
			ADDI("unaligned");
			ADDN(bBuf, NUMBER_TYPE_UCHAR);
			break;
		}

	case ILOPCODE_TAIL_:
		{
			pCurInstr += 2;
			ADDI("tail.");
			break;
		}

	case ILOPCODE_VOLATILE_:
		{
			pCurInstr += 2;
			ADDI("volatile.");
			break;
		}

	case ILOPCODE_READONLY_:
		{
			pCurInstr += 2;
			ADDI("readonly.");
			break;
		}
	}


	//
	// get instruction
	//

getinstr:

	//
	// Check if it's a one-byte instr
	//

	if (CurInstr >= 0x00 && CurInstr <= 0xE0)
	{
		pCurInstr += 1;

		switch (CurInstr)
		{

		case ILOPCODE_NOP:
			{
				ADDI("nop");
				break;
			}

		case ILOPCODE_BREAK:
			{
				ADDI("break");
				break;
			}

		case ILOPCODE_LDARG_0:
			{
				ADDI("ldarg.0");
				break;
			}

		case ILOPCODE_LDARG_1:
			{
				ADDI("ldarg.1");
				break;
			}

		case ILOPCODE_LDARG_2:
			{
				ADDI("ldarg.2");
				break;
			}

		case ILOPCODE_LDARG_3:
			{
				ADDI("ldarg.3");
				break;
			}

		case ILOPCODE_LDLOC_0:
			{
				ADDI("ldloc.0");
				break;
			}

		case ILOPCODE_LDLOC_1:
			{
				ADDI("ldloc.1");
				break;
			}

		case ILOPCODE_LDLOC_2:
			{
				ADDI("ldloc.2");
				break;
			}

		case ILOPCODE_LDLOC_3:
			{
				ADDI("ldloc.3");
				break;
			}

		case ILOPCODE_STLOC_0:
			{
				ADDI("stloc.0");
				break;
			}

		case ILOPCODE_STLOC_1:
			{
				ADDI("stloc.1");
				break;
			}

		case ILOPCODE_STLOC_2:
			{
				ADDI("stloc.2");
				break;
			}

		case ILOPCODE_STLOC_3:
			{
				ADDI("stloc.3");
				break;
			}

		case ILOPCODE_LDARG_S:
			{
				ADDI("ldarg.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr++;
				ADDN(bBuf, NUMBER_TYPE_UCHAR);
				break;
			}

		case ILOPCODE_LDARGA_S:
			{
				ADDI("ldarga.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr++;
				ADDN(bBuf, NUMBER_TYPE_UCHAR);
				break;
			}

		case ILOPCODE_STARG_S:
			{
				ADDI("starg.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr++;
				ADDN(bBuf, NUMBER_TYPE_UCHAR);
				break;
			}

		case ILOPCODE_LDLOC_S:
			{
				ADDI("ldloc.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr++;
				ADDN(bBuf, NUMBER_TYPE_UCHAR);
				break;
			}

		case ILOPCODE_LDLOCA_S:
			{
				ADDI("ldloca.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr++;
				ADDN(bBuf, NUMBER_TYPE_UCHAR);
				break;
			}

		case ILOPCODE_STLOC_S:
			{
				ADDI("stloc.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr++;
				ADDN(bBuf, NUMBER_TYPE_UCHAR);
				break;
			}

		case ILOPCODE_LDNULL:
			{
				ADDI("ldnull");
				break;
			}

		case ILOPCODE_LDC_I4_M1:
			{
				ADDI("ldc.i4.m1");
				break;
			}

		case ILOPCODE_LDC_I4_0:
			{
				ADDI("ldc.i4.0");
				break;
			}

		case ILOPCODE_LDC_I4_1:
			{
				ADDI("ldc.i4.1");
				break;
			}

		case ILOPCODE_LDC_I4_2:
			{
				ADDI("ldc.i4.2");
				break;
			}

		case ILOPCODE_LDC_I4_3:
			{
				ADDI("ldc.i4.3");
				break;
			}

		case ILOPCODE_LDC_I4_4:
			{
				ADDI("ldc.i4.4");
				break;
			}

		case ILOPCODE_LDC_I4_5:
			{
				ADDI("ldc.i4.5");
				break;
			}

		case ILOPCODE_LDC_I4_6:
			{
				ADDI("ldc.i4.6");
				break;
			}

		case ILOPCODE_LDC_I4_7:
			{
				ADDI("ldc.i4.7");
				break;
			}

		case ILOPCODE_LDC_I4_8:
			{
				ADDI("ldc.i4.8");
				break;
			}

		case ILOPCODE_LDC_I4_S:
			{
				ADDI("ldc.i4.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr++;
				ADDN(bBuf, NUMBER_TYPE_CHAR);
				break;
			}

		case ILOPCODE_LDC_I4:
			{
				ADDI("ldc.i4");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_INT);
				break;
			}

		case ILOPCODE_LDC_I8:
			{
				ADDI("ldc.i8");
				GET(pCurInstr, qwBuf, QWORD);
				pCurInstr += 8;
				ADDN(qwBuf, NUMBER_TYPE_INT64);
				break;
			}

		case ILOPCODE_LDC_R4:
			{
				ADDI("ldc.r4");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_FLOAT);
				break;
			}

		case ILOPCODE_LDC_R8:
			{
				ADDI("ldc.r8");
				GET(pCurInstr, qwBuf, QWORD);
				pCurInstr += 8;
				ADDN(qwBuf, NUMBER_TYPE_DOUBLE);
				break;
			}

		case ILOPCODE_DUP:
			{
				ADDI("dup");
				break;
			}

		case ILOPCODE_POP:
			{
				ADDI("pop");
				break;
			}

		case ILOPCODE_JMP:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("jmp", dwBuf);
				break;
			}

		case ILOPCODE_CALL:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("call", dwBuf);
				break;
			}

		case ILOPCODE_CALLI:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("calli", dwBuf);
				break;
			}

		case ILOPCODE_RET:
			{
				ADDI("ret");
				break;
			}

		case ILOPCODE_BR_S:
			{
				ADDI("br.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BRFALSE_S:
			{
				ADDI("brfalse.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BRTRUE_S:
			{
				ADDI("brtrue.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BEQ_S:
			{
				ADDI("beq.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BGE_S:
			{
				ADDI("bge.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BGT_S:
			{
				ADDI("bgt.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BLE_S:
			{
				ADDI("ble.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BLT_S:
			{
				ADDI("blt.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BNE_UN_S:
			{
				ADDI("bne.un.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BGE_UN_S:
			{
				ADDI("bge.un.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BGT_UN_S:
			{
				ADDI("bgt.un.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BLE_UN_S:
			{
				ADDI("ble.un.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BLT_UN_S:
			{
				ADDI("blt.un.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_BR:
			{
				ADDI("br");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BRFALSE:
			{
				ADDI("brfalse");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BRTRUE:
			{
				ADDI("brtrue");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BEQ:
			{
				ADDI("beq");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BGE:
			{
				ADDI("bge");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BGT:
			{
				ADDI("bgt");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BLE:
			{
				ADDI("ble");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BLT:
			{
				ADDI("blt");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BNE_UN:
			{
				ADDI("bne.un");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BGE_UN:
			{
				ADDI("bge.un");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BGT_UN:
			{
				ADDI("bgt.un");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BLE_UN:
			{
				ADDI("ble.un");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_BLT_UN:
			{
				ADDI("blt.un");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_SWITCH:
			{
				//
				// The switch is followed by a dword and an array
				// of dwords, the first dword tells how many dwords will follow
				// every dword in the array represents an int32 offset
				//

				GET(pCurInstr, dwBuf, DWORD);
				VALIDATE(pCurInstr, (dwBuf + 1) * sizeof (DWORD));
				ADDI("switch");
				pCurInstr += ((dwBuf + 1) * sizeof (DWORD));
				break;
			}

		case ILOPCODE_LDIND_I1:
			{
				ADDI("ldind.i1");
				break;
			}

		case ILOPCODE_LDIND_U1:
			{
				ADDI("ldind.u1");
				break;
			}

		case ILOPCODE_LDIND_I2:
			{
				ADDI("ldind.i2");
				break;
			}

		case ILOPCODE_LDIND_U2:
			{
				ADDI("ldind.u2");
				break;
			}

		case ILOPCODE_LDIND_I4:
			{
				ADDI("ldind.i4");
				break;
			}

		case ILOPCODE_LDIND_U4:
			{
				ADDI("ldind.u4");
				break;
			}

		case ILOPCODE_LDIND_I8:
			{
				ADDI("ldind.i8");
				break;
			}

		case ILOPCODE_LDIND_I:
			{
				ADDI("ldind.i");
				break;
			}

		case ILOPCODE_LDIND_R4:
			{
				ADDI("ldind.r4");
				break;
			}

		case ILOPCODE_LDIND_R8:
			{
				ADDI("ldind.r8");
				break;
			}

		case ILOPCODE_LDIND_REF:
			{
				ADDI("ldind.ref");
				break;
			}

		case ILOPCODE_STIND_REF:
			{
				ADDI("stind.ref");
				break;
			}

		case ILOPCODE_STIND_I1:
			{
				ADDI("stind.i1");
				break;
			}

		case ILOPCODE_STIND_I2:
			{
				ADDI("stind.i2");
				break;
			}

		case ILOPCODE_STIND_I4:
			{
				ADDI("stind.i4");
				break;
			}

		case ILOPCODE_STIND_I8:
			{
				ADDI("stind.i8");
				break;
			}

		case ILOPCODE_STIND_R4:
			{
				ADDI("stind.r4");
				break;
			}

		case ILOPCODE_STIND_R8:
			{
				ADDI("stind.r8");
				break;
			}

		case ILOPCODE_ADD:
			{
				ADDI("add");
				break;
			}

		case ILOPCODE_SUB:
			{
				ADDI("sub");
				break;
			}

		case ILOPCODE_MUL:
			{
				ADDI("mul");
				break;
			}

		case ILOPCODE_DIV:
			{
				ADDI("div");
				break;
			}

		case ILOPCODE_DIV_UN:
			{
				ADDI("div.un");
				break;
			}

		case ILOPCODE_REM:
			{
				ADDI("rem");
				break;
			}

		case ILOPCODE_REM_UN:
			{
				ADDI("rem.un");
				break;
			}

		case ILOPCODE_AND:
			{
				ADDI("and");
				break;
			}

		case ILOPCODE_OR:
			{
				ADDI("or");
				break;
			}

		case ILOPCODE_XOR:
			{
				ADDI("xor");
				break;
			}

		case ILOPCODE_SHL:
			{
				ADDI("shl");
				break;
			}

		case ILOPCODE_SHR:
			{
				ADDI("shr");
				break;
			}

		case ILOPCODE_SHR_UN:
			{
				ADDI("shr.un");
				break;
			}

		case ILOPCODE_NEG:
			{
				ADDI("neg");
				break;
			}

		case ILOPCODE_NOT:
			{
				ADDI("not");
				break;
			}

		case ILOPCODE_CONV_I1:
			{
				ADDI("conv.i1");
				break;
			}

		case ILOPCODE_CONV_I2:
			{
				ADDI("conv.i2");
				break;
			}

		case ILOPCODE_CONV_I4:
			{
				ADDI("conv.i4");
				break;
			}

		case ILOPCODE_CONV_I8:
			{
				ADDI("conv.i8");
				break;
			}

		case ILOPCODE_CONV_R4:
			{
				ADDI("conv.r4");
				break;
			}

		case ILOPCODE_CONV_R8:
			{
				ADDI("conv.r8");
				break;
			}

		case ILOPCODE_CONV_U4:
			{
				ADDI("conv.u4");
				break;
			}

		case ILOPCODE_CONV_U8:
			{
				ADDI("conv.u8");
				break;
			}

		case ILOPCODE_CALLVIRT:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("callvirt", dwBuf);
				break;
			}

		case ILOPCODE_CPOBJ:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("cpobj", dwBuf);
				break;
			}

		case ILOPCODE_LDOBJ:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldobj", dwBuf);
				break;
			}

		case ILOPCODE_LDSTR:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldstr", dwBuf);
				break;
			}

		case ILOPCODE_NEWOBJ:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("newobj", dwBuf);
				break;
			}

		case ILOPCODE_CASTCLASS:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("castclass", dwBuf);
				break;
			}

		case ILOPCODE_ISINST:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("isinst", dwBuf);
				break;
			}

		case ILOPCODE_CONV_R_UN:
			{
				ADDI("conv.r.un");
				break;
			}

		case ILOPCODE_UNBOX:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("unbox", dwBuf);
				break;
			}

		case ILOPCODE_THROW:
			{
				ADDI("throw");
				break;
			}

		case ILOPCODE_LDFLD:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldfld", dwBuf);
				break;
			}

		case ILOPCODE_LDFLDA:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldflda", dwBuf);
				break;
			}

		case ILOPCODE_STFLD:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("stfld", dwBuf);
				break;
			}

		case ILOPCODE_LDSFLD:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldsfld", dwBuf);
				break;
			}

		case ILOPCODE_LDSFLDA:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldsflda", dwBuf);
				break;
			}

		case ILOPCODE_STSFLD:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("stsfld", dwBuf);
				break;
			}

		case ILOPCODE_STOBJ:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("stobj", dwBuf);
				break;
			}

		case ILOPCODE_CONV_OVF_I1_UN:
			{
				ADDI("conv.ovf.i1.un");
				break;
			}

		case ILOPCODE_CONV_OVF_I2_UN:
			{
				ADDI("conv.ovf.i2.un");
				break;
			}

		case ILOPCODE_CONV_OVF_I4_UN:
			{
				ADDI("conv.ovf.i4.un");
				break;
			}

		case ILOPCODE_CONV_OVF_I8_UN:
			{
				ADDI("conv.ovf.i8.un");
				break;
			}

		case ILOPCODE_CONV_OVF_U1_UN:
			{
				ADDI("conv.ovf.u1.un");
				break;
			}

		case ILOPCODE_CONV_OVF_U2_UN:
			{
				ADDI("conv.ovf.u2.un");
				break;
			}

		case ILOPCODE_CONV_OVF_U4_UN:
			{
				ADDI("conv.ovf.u4.un");
				break;
			}

		case ILOPCODE_CONV_OVF_U8_UN:
			{
				ADDI("conv.ovf.u8.un");
				break;
			}

		case ILOPCODE_CONV_OVF_I_UN:
			{
				ADDI("conv.ovf.i.un");
				break;
			}

		case ILOPCODE_CONV_OVF_U_UN:
			{
				ADDI("conv.ovf.u.un");
				break;
			}

		case ILOPCODE_BOX:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("box", dwBuf);
				break;
			}

		case ILOPCODE_NEWARR:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("newarr", dwBuf);
				break;
			}

		case ILOPCODE_LDLEN:
			{
				ADDI("ldlen");
				break;
			}

		case ILOPCODE_LDELEMA:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldelema", dwBuf);
				break;
			}

		case ILOPCODE_LDELEM_I1:
			{
				ADDI("ldelem.i1");
				break;
			}

		case ILOPCODE_LDELEM_U1:
			{
				ADDI("ldelem.u1");
				break;
			}

		case ILOPCODE_LDELEM_I2:
			{
				ADDI("ldelem.i2");
				break;
			}

		case ILOPCODE_LDELEM_U2:
			{
				ADDI("ldelem.u2");
				break;
			}

		case ILOPCODE_LDELEM_I4:
			{
				ADDI("ldelem.i4");
				break;
			}

		case ILOPCODE_LDELEM_U4:
			{
				ADDI("ldelem.u4");
				break;
			}

		case ILOPCODE_LDELEM_I8:
			{
				ADDI("ldelem.i1");
				break;
			}

		case ILOPCODE_LDELEM_I:
			{
				ADDI("ldelem.i");
				break;
			}

		case ILOPCODE_LDELEM_R4:
			{
				ADDI("ldelem.r4");
				break;
			}

		case ILOPCODE_LDELEM_R8:
			{
				ADDI("ldelem.r8");
				break;
			}

		case ILOPCODE_LDELEM_REF:
			{
				ADDI("ldelem.ref");
				break;
			}

		case ILOPCODE_STELEM_I:
			{
				ADDI("stelem.i");
				break;
			}

		case ILOPCODE_STELEM_I1:
			{
				ADDI("stelem.i1");
				break;
			}

		case ILOPCODE_STELEM_I2:
			{
				ADDI("stelem.i2");
				break;
			}

		case ILOPCODE_STELEM_I4:
			{
				ADDI("stelem.i4");
				break;
			}

		case ILOPCODE_STELEM_I8:
			{
				ADDI("stelem.i8");
				break;
			}

		case ILOPCODE_STELEM_R4:
			{
				ADDI("stelem.r4");
				break;
			}

		case ILOPCODE_STELEM_R8:
			{
				ADDI("stelem.r8");
				break;
			}

		case ILOPCODE_STELEM_REF:
			{
				ADDI("stelem.ref");
				break;
			}

		case ILOPCODE_LDELEM:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldelem", dwBuf);
				break;
			}

		case ILOPCODE_STELEM:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("stelem", dwBuf);
				break;
			}

		case ILOPCODE_UNBOX_ANY:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("unbox.any", dwBuf);
				break;
			}

		case ILOPCODE_CONV_OVF_I1:
			{
				ADDI("conv.ovf.i1");
				break;
			}

		case ILOPCODE_CONV_OVF_U1:
			{
				ADDI("conv.ovf.u1");
				break;
			}

		case ILOPCODE_CONV_OVF_I2:
			{
				ADDI("conv.ovf.i2");
				break;
			}

		case ILOPCODE_CONV_OVF_U2:
			{
				ADDI("conv.ovf.u2");
				break;
			}

		case ILOPCODE_CONV_OVF_I4:
			{
				ADDI("conv.ovf.i4");
				break;
			}

		case ILOPCODE_CONV_OVF_U4:
			{
				ADDI("conv.ovf.u4");
				break;
			}

		case ILOPCODE_CONV_OVF_I8:
			{
				ADDI("conv.ovf.i8");
				break;
			}

		case ILOPCODE_CONV_OVF_U8:
			{
				ADDI("conv.ovf.u8");
				break;
			}

		case ILOPCODE_REFANYVAL:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("refanyval", dwBuf);
				break;
			}

		case ILOPCODE_CKFINITE:
			{
				ADDI("ckfinite");
				break;
			}

		case ILOPCODE_MKREFANY:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("mkrefany", dwBuf);
				break;
			}

		case ILOPCODE_LDTOKEN:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldtoken", dwBuf);
				break;
			}

		case ILOPCODE_CONV_U2:
			{
				ADDI("conv.u2");
				break;
			}

		case ILOPCODE_CONV_U1:
			{
				ADDI("conv.u1");
				break;
			}

		case ILOPCODE_CONV_I:
			{
				ADDI("conv.i");
				break;
			}

		case ILOPCODE_CONV_OVF_I:
			{
				ADDI("conv.ovf.i");
				break;
			}

		case ILOPCODE_CONV_OVF_U:
			{
				ADDI("conv.ovf.u");
				break;
			}

		case ILOPCODE_ADD_OVF:
			{
				ADDI("add.ovf");
				break;
			}

		case ILOPCODE_ADD_OVF_UN:
			{
				ADDI("add.ovf.un");
				break;
			}

		case ILOPCODE_MUL_OVF:
			{
				ADDI("mul.ovf");
				break;
			}

		case ILOPCODE_MUL_OVF_UN:
			{
				ADDI("mul.ovf.un");
				break;
			}

		case ILOPCODE_SUB_OVF:
			{
				ADDI("sub.ovf");
				break;
			}

		case ILOPCODE_SUB_OVF_UN:
			{
				ADDI("sub.ovf.un");
				break;
			}

		case ILOPCODE_ENDFINALLY:
			{
				ADDI("endfinally");
				break;
			}

		case ILOPCODE_LEAVE:
			{
				ADDI("leave");
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDN(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}

		case ILOPCODE_LEAVE_S:
			{
				ADDI("leave.s");
				GET(pCurInstr, bBuf, BYTE);
				pCurInstr += 1;
				ADDN(bBuf, NUMBER_TYPE_SMALL_BRANCH);
				break;
			}

		case ILOPCODE_STIND_I:
			{
				ADDI("stind.i");
				break;
			}

		case ILOPCODE_CONV_U:
			{
				ADDI("conv.u");
				break;
			}

		default:
			{
				return FALSE;
			}

		} // end switch
	}

	//
	// Two bytes instruction
	//

	else
	{
		GET(pCurInstr, CurInstr, WORD);

		pCurInstr += 2;

		switch (CurInstr)
		{
			
		case ILOPCODE_ARGLIST:
			{
				ADDI("arglist");
				break;
			}

		case ILOPCODE_CEQ:
			{
				ADDI("ceq");
				break;
			}

		case ILOPCODE_CGT:
			{
				ADDI("cgt");
				break;
			}

		case ILOPCODE_CGT_UN:
			{
				ADDI("cgt.un");
				break;
			}

		case ILOPCODE_CLT:
			{
				ADDI("clt");
				break;
			}

		case ILOPCODE_CLT_UN:
			{
				ADDI("clt.un");
				break;
			}

		case ILOPCODE_LDFTN:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldftn", dwBuf);
				break;
			}

		case ILOPCODE_LDVIRTFTN:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("ldvirtftn", dwBuf);
				break;
			}

		case ILOPCODE_LDARG:
			{
				ADDI("ldarg");
				GET(pCurInstr, wBuf, WORD);
				pCurInstr += 2;
				ADDN(wBuf, NUMBER_TYPE_USHORT);
				break;
			}

		case ILOPCODE_LDARGA:
			{
				ADDI("ldarga");
				GET(pCurInstr, wBuf, WORD);
				pCurInstr += 2;
				ADDN(wBuf, NUMBER_TYPE_USHORT);
				break;
			}

		case ILOPCODE_STARG:
			{
				ADDI("starg");
				GET(pCurInstr, wBuf, WORD);
				pCurInstr += 2;
				ADDN(wBuf, NUMBER_TYPE_USHORT);
				break;
			}

		case ILOPCODE_LDLOC:
			{
				ADDI("ldloc");
				GET(pCurInstr, wBuf, WORD);
				pCurInstr += 2;
				ADDN(wBuf, NUMBER_TYPE_USHORT);
				break;
			}

		case ILOPCODE_LDLOCA:
			{
				ADDI("ldloca");
				GET(pCurInstr, wBuf, WORD);
				pCurInstr += 2;
				ADDN(wBuf, NUMBER_TYPE_USHORT);
				break;
			}

		case ILOPCODE_STLOC:
			{
				ADDI("stloc");
				GET(pCurInstr, wBuf, WORD);
				pCurInstr += 2;
				ADDN(wBuf, NUMBER_TYPE_USHORT);
				break;
			}

		case ILOPCODE_LOCALLOC:
			{
				ADDI("localloc");
				break;
			}

		case ILOPCODE_ENDFILTER:
			{
				ADDI("endfilter");
				break;
			}

		case ILOPCODE_INITOBJ:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("initobj", dwBuf);
				break;
			}

		case ILOPCODE_CPBLK:
			{
				ADDI("cpblk");
				break;
			}

		case ILOPCODE_INITBLK:
			{
				ADDI("initblk");
				break;
			}

		case ILOPCODE_RETHROW:
			{
				ADDI("rethrow");
				break;
			}

		case ILOPCODE_SIZEOF:
			{
				GET(pCurInstr, dwBuf, DWORD);
				pCurInstr += 4;
				ADDIT("sizeof", dwBuf);
				break;
			}

		case ILOPCODE_REFANYTYPE_V2:
			{
				ADDI("refanytype.v2");
				break;
			}

		default:
			{
				return FALSE;
			}
		}
	}


	//
	// End

	ilop->Size = (UINT) (((ULONG_PTR) pCurInstr) - 
		((ULONG_PTR) pMemory));
	
	return TRUE;
}

BOOL DisasMSIL(BYTE *pMemory, 
			   UINT MemorySize,
			   DISASMSIL_OFFSET CodeBase,
			   ILOPCODE_STRUCT *iloparray,
			   UINT nOpcodeStructs,
			   UINT *nDisassembledInstr)
{
	if (nDisassembledInstr) *nDisassembledInstr = 0;

	if (MemorySize == 0 || 
		nOpcodeStructs == 0 ||
		iloparray == NULL) 
		return FALSE;

	BYTE *pCurMem = pMemory;
	UINT RemSize = MemorySize;
	DISASMSIL_OFFSET CurBase = CodeBase;

	for (UINT x = 0; x < nOpcodeStructs; x++)
	{
		if (!GetSingleMSILInstr(pCurMem, RemSize, CurBase, &iloparray[x]))
		{
			if (x == 0) return FALSE;
			break;
		}

		pCurMem += iloparray[x].Size;
		CurBase += iloparray[x].Size;
		RemSize -= iloparray[x].Size;

		if (nDisassembledInstr) *nDisassembledInstr = x + 1;
	}

	return TRUE;
}