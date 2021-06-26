#include <stdio.h>
#include <windows.h>
#include "clrLoader.h"
#include "nvcoree/corinfo.h"
#include "nvcoree/corjit.h"
#include "nvcoree/DisasMSIL.cpp"
#pragma warning( disable:4996 )

bool readBinFile(const char fileName[], char*& bufPtr, DWORD& length) {
	if (FILE* fp = fopen(fileName, "rb")) {
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		bufPtr = new char[length + 1];
		fseek(fp, 0, SEEK_SET);
		fread(bufPtr, sizeof(char), length, fp);
		return true;
	}
	else return false;
}

typedef int(__stdcall* compileMethod_def)( ICorJitInfo*, ICorJitInfo*, CORINFO_METHOD_INFO*, unsigned, BYTE**, ULONG* );
compileMethod_def compileMethod;
struct JIT { compileMethod_def compileMethod; };


// ref: https://www.codeproject.com/Articles/26060/NET-Internals-and-Code-Injection
VOID DisplayMethodAndCalls(ICorJitInfo* comp, CORINFO_METHOD_INFO* info) {
	const char *szMethodName = NULL, *szClassName = NULL;
	szMethodName = comp->getMethodName(info->ftn, &szClassName);
	printf("    >> Invoke %s() ...\n", szMethodName);

		
#define MAX_INSTR      100
		ILOPCODE_STRUCT ilopar[MAX_INSTR];

		DISASMSIL_OFFSET CodeBase = 0;

		BYTE* pCur = info->ILCode;
		UINT nSize = info->ILCodeSize;

		UINT nDisasmedInstr;

		while (DisasMSIL(pCur, nSize, CodeBase, ilopar, MAX_INSTR, &nDisasmedInstr)) {
			DISASMSIL_OFFSET next = ilopar[nDisasmedInstr - 1].Offset - CodeBase;
			next += ilopar[nDisasmedInstr - 1].Size;
			pCur += next;
			nSize -= next;
			CodeBase += next;
			for (size_t i = 0; i < nDisasmedInstr; i++)
				printf("           %s\n", ilopar[i].Mnemonic);
		}
}

int __stdcall my_compileMethod(ICorJitInfo* classthis, ICorJitInfo* comp, CORINFO_METHOD_INFO* info, unsigned flags, BYTE** nativeEntry, ULONG* nativeSizeOfCode) {
	DisplayMethodAndCalls(comp, info);
	
	return compileMethod(classthis, comp, info, flags, nativeEntry, nativeSizeOfCode);
}

bool HookJIT(LPWSTR frameworkDir) {
	LoadLibraryA("mscoree.dll");

	wchar_t abs_clrJit[MAX_PATH], abs_mscorJit[MAX_PATH];
	wsprintf(abs_clrJit, L"%s\\clrjit.dll", frameworkDir);      // .NET Framework 4+
	wsprintf(abs_mscorJit, L"%s\\mscorjit.dll", frameworkDir);  // .NET Framework 2 ~ 3.5
	auto modLibJit = LoadLibraryW(abs_clrJit) ? LoadLibraryW(abs_clrJit) : LoadLibraryW(abs_mscorJit);
	if (auto ptrGetJit = (size_t(__stdcall*)()) GetProcAddress(modLibJit, "getJit"))
		if (JIT* pJit = (JIT*)*((ULONG_PTR*)ptrGetJit())) {
			DWORD OldProtect;
			VirtualProtect(pJit, sizeof(ULONG_PTR), PAGE_READWRITE, &OldProtect);
			compileMethod = pJit->compileMethod;
			pJit->compileMethod = &my_compileMethod;
			VirtualProtect(pJit, sizeof(ULONG_PTR), OldProtect, &OldProtect);
			return true;
		}
	return false;
}

int wmain(int argc, wchar_t* argv[]) {
	PCHAR ptrBinary; DWORD lenBinary;
	if (!readBinFile("C:/dotNet2.0_PoC_x86.exe", ptrBinary, lenBinary))
		return -1;

	printf("\n --- Enumerate Available CLR Runtime ---\n");
	wchar_t szCLR_Version[MAX_PATH], sz_CLR_Path[MAX_PATH];
	if (!bruteforce_CLRhost(szCLR_Version, sz_CLR_Path)) return -1;

	printf("\n --- Install CLR Runtime in Process ---\n");
	wprintf(L"[+] Select Runtime: %s\n", szCLR_Version);
	wprintf(L"[+] Framework At: %s\n", sz_CLR_Path);
	//ICorRuntimeHost* pRuntimeHost = getCorRtHost_byVersion(L"v2.0.50727");
	ICorRuntimeHost* pRuntimeHost = getCorRtHost_byVersion(szCLR_Version);

	printf("\n --- Hooking JIT Engine ---\n");
	printf("[+] Install Hook on JIT Engine: %s\n", HookJIT(sz_CLR_Path) ? "OK": "Fail");

	printf("\n --- Execute .NET Module ---\n");
	_MethodInfoPtr pMethodInfo = NULL;
	// fetch the default domain
	if (auto pDefaultAppDomain = getDefaultDomain(pRuntimeHost))
		// load .net module into CLR (PE binary)
		if (_AssemblyPtr pAssembly = getAssembly_fromBinary(pDefaultAppDomain, LPBYTE(ptrBinary), (lenBinary)))
			//A ssembly.EntryPoint Property
			if (FAILED(pAssembly->get_EntryPoint(&pMethodInfo))) {
				printf("[!] pAssembly->get_EntryPoint(...) failed\n");
				return -1;
			}
			else printf("[+] pAssembly->get_EntryPoint(...) succeeded\n");

	/* EntryPoint.Invoke(new string[] { argv_1, argv_2, argv_3, ... } ) */
	if (HRESULT hr = pMethodInfo->raw_Invoke_3(VARIANT(), newArguments(argc, argv), &VARIANT()) < 0) {
		printf("[!] pMethodInfo->Invoke_3(...) failed, hr = %X\n", hr);
		return -1;
	}
	else printf("[+] pMethodInfo->Invoke_3(...) succeeded\n");
	return 0;
}

