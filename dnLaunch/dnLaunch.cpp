#include <stdio.h>
#include <windows.h>
#include <mscoree.h>
#include <metahost.h>
#pragma comment(lib, "MSCorEE.lib")
#pragma warning( disable:4996 )

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import "mscorlib.tlb" auto_rename
using namespace mscorlib;

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
ICorRuntimeHost* getCorRtHost_byVersion(LPCWSTR sz_runtimeVersion) {
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	ICorRuntimeHost* pRuntimeHost = NULL;
	ICLRMetaHost* pMetaHost = NULL;
	BOOL bLoadable;

	/* Get ICLRMetaHost instance */
	if (FAILED(CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (VOID**)&pMetaHost)))
	{
		printf("[!] CLRCreateInstance(...) failed\n");
		return NULL;
	}
	else printf("[+] CLRCreateInstance(...) succeeded\n");

	/* Get ICLRRuntimeInfo instance */
	if (FAILED(pMetaHost->GetRuntime(sz_runtimeVersion, IID_ICLRRuntimeInfo, (VOID**)&pRuntimeInfo))) {
		printf("[!] pMetaHost->GetRuntime(...) failed\n");
		return NULL;
	}
	else printf("[+] pMetaHost->GetRuntime(...) succeeded\n");

	/* Check if the specified runtime can be loaded */
	if (FAILED(pRuntimeInfo->IsLoadable(&bLoadable)) || !bLoadable) {
		printf("[!] pRuntimeInfo->IsLoadable(...) failed\n");
		return NULL;
	}
	else printf("[+] pRuntimeInfo->IsLoadable(...) succeeded\n");

	/* Get ICorRuntimeHost instance */
	if (FAILED(pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&pRuntimeHost))) {
		printf("[!] pRuntimeInfo->GetInterface(...) failed\n");
		return NULL;
	}
	else printf("[+] pRuntimeInfo->GetInterface(...) succeeded\n");

	/* Start the CLR */
	if (FAILED(pRuntimeHost->Start())) {
		printf("[!] pRuntimeHost->Start() failed\n");
		return NULL;
	}
	else printf("[+] pRuntimeHost->Start() succeeded\n");
	return pRuntimeHost;
}
_AppDomainPtr getDefaultDomain(ICorRuntimeHost* pRuntimeHost) {
	IUnknownPtr pAppDomainThunk = NULL;
	if (FAILED(pRuntimeHost->GetDefaultDomain(&pAppDomainThunk))) {
		printf("[!] pRuntimeHost->GetDefaultDomain(...) failed\n");
		return NULL;
	}
	else printf("[+] pRuntimeHost->GetDefaultDomain(...) succeeded\n");

	/* Equivalent of System.AppDomain.CurrentDomain in C# */
	_AppDomainPtr pDefaultAppDomain = NULL;
	if (FAILED(pAppDomainThunk->QueryInterface(__uuidof(_AppDomain), (LPVOID*)&pDefaultAppDomain))) {
		printf("[!] pAppDomainThunk->QueryInterface(...) failed\n");
		return NULL;
	}
	else printf("[+] pAppDomainThunk->QueryInterface(...) succeeded\n");
	return pDefaultAppDomain;
}
_AssemblyPtr getAssembly_fromBinary(_AppDomainPtr pDefaultAppDomain, LPBYTE rawData, ULONG lenRawData) {
	_AssemblyPtr pAssembly = NULL;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, new SAFEARRAYBOUND{ lenRawData , 0 });

	void* pvData = NULL;
	if (FAILED(SafeArrayAccessData(pSafeArray, &pvData))) {
		printf("[!] SafeArrayAccessData(...) failed\n");
		return -1;
	}
	else printf("[+] SafeArrayAccessData(...) succeeded\n");

	memcpy(pvData, rawData, lenRawData);
	if (FAILED(SafeArrayUnaccessData(pSafeArray))) {
		printf("[!] SafeArrayUnaccessData(...) failed\n");
		return NULL;
	}
	else printf("[+] SafeArrayUnaccessData(...) succeeded\n");

	/* Equivalent of System.AppDomain.CurrentDomain.Load(byte[] rawAssembly) */
	if (FAILED(pDefaultAppDomain->raw_Load_3(pSafeArray, &pAssembly))) {
		printf("[!] pDefaultAppDomain->Load_3(...) failed\n");
		return NULL;
	}
	else printf("[+] pDefaultAppDomain->Load_3(...) succeeded\n");
	return pAssembly;
}
SAFEARRAY* newArguments(int argc, wchar_t** argv) {
	VARIANT args;
	args.vt = VT_ARRAY | VT_BSTR;
	args.parray = SafeArrayCreate(VT_BSTR, 1, new SAFEARRAYBOUND{ ULONG(argc) , 0 });
	for (int i = 0; i < argc; i++) SafeArrayPutElement(args.parray, (LONG*)&i, SysAllocString(argv[i]));

	SAFEARRAY* params = SafeArrayCreate(VT_VARIANT, 1, new SAFEARRAYBOUND{ 1, 0 });

	LONG indx = 0;
	SafeArrayPutElement(params, &indx, &args);
	return params;
}
// https://blog.xpnsec.com/hiding-your-dotnet-etw/
ICorRuntimeHost* bruteforce_CLRhost() {
	ICLRMetaHost* metaHost = NULL;
	IEnumUnknown* runtime = NULL;
	ICLRRuntimeInfo* runtimeInfo = nullptr;
	DWORD bytes;
	if (CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost) != S_OK) {
		printf("[x] Error: CLRCreateInstance(..)\n");
		return NULL;
	}

	if (metaHost->EnumerateInstalledRuntimes(&runtime) != S_OK) {
		printf("[x] Error: EnumerateInstalledRuntimes(..)\n");
		return NULL;
	}
	auto frameworkName = (LPWSTR)LocalAlloc(LPTR, 2048);
	IUnknown* enumRuntime = nullptr;
	// Enumerate through runtimes and show supported frameworks
	while (runtime->Next(1, &enumRuntime, 0) == S_OK) {
		if (enumRuntime->QueryInterface<ICLRRuntimeInfo>(&runtimeInfo) == S_OK) {
			if (runtimeInfo != NULL) {
				memset(frameworkName, 0, sizeof(frameworkName)); bytes = 2048;
				runtimeInfo->GetRuntimeDirectory(frameworkName, &bytes);
				wprintf(L"[*] .NET Dir: %s\n", frameworkName);
				memset(frameworkName, 0, sizeof(frameworkName)); bytes = 2048;
				runtimeInfo->GetVersionString(frameworkName, &bytes);
				wprintf(L"[*] Supported Framework: %s\n", frameworkName);
				
	
			}
		}
	}
	wprintf(L"[*] Current Used Framework: %s\n", frameworkName);
	return getCorRtHost_byVersion(frameworkName);
}

#include "corinfo.h"
#include "corjit.h"



typedef int(__stdcall* compileMethod_def)(ICorJitInfo* classthis, ICorJitInfo* comp,
	CORINFO_METHOD_INFO* info, unsigned flags,
	BYTE** nativeEntry, ULONG* nativeSizeOfCode);
compileMethod_def compileMethod;
struct JIT
{
	compileMethod_def compileMethod;
};


int __stdcall my_compileMethod(ICorJitInfo* classthis, ICorJitInfo* comp,
	CORINFO_METHOD_INFO* info,
	unsigned flags, BYTE** nativeEntry, ULONG* nativeSizeOfCode) {
	
	//const char* szMethodName = NULL;
//	const char* szClassName = NULL;
	auto attribs = comp->getMethodAttribs(info->ftn);
	printf("attribs = %x\n", attribs);

	if (attribs & CorInfoFlag::CORINFO_FLG_PROTECTED)
	{
		std::cout << "\t" << "CORINFO_FLG_PROTECTED" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_STATIC)
	{
		std::cout << "\t" << "CORINFO_FLG_STATIC" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_FINAL)
	{
		std::cout << "\t" << "CORINFO_FLG_FINAL" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_SYNCH)
	{
		std::cout << "\t" << "CORINFO_FLG_SYNCH" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_VIRTUAL)
	{
		std::cout << "\t" << "CORINFO_FLG_VIRTUAL" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_NATIVE)
	{
		std::cout << "\t" << "CORINFO_FLG_NATIVE" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_INTRINSIC_TYPE)
	{
		std::cout << "\t" << "CORINFO_FLG_INTRINSIC_TYPE: This type is marked by [Intrinsic]" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_ABSTRACT)
	{
		std::cout << "\t" << "CORINFO_FLG_ABSTRACT" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_EnC)
	{
		std::cout << "\t" << "CORINFO_FLG_EnC: member was added by Edit'n'Continue" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_FORCEINLINE)
	{
		std::cout << "\t" << "CORINFO_FLG_FORCEINLINE: The method should be inlined if possible" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_SHAREDINST)
	{
		std::cout << "\t" << "CORINFO_FLG_SHAREDINST: the code for this method is shared between different generic instantiations (also set on classes/types)" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_DELEGATE_INVOKE)
	{
		std::cout << "\t" << "CORINFO_FLG_DELEGATE_INVOKE Delegate" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_PINVOKE)
	{
		std::cout << "\t" << "CORINFO_FLG_PINVOKE: Is a P/Invoke call" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_SECURITYCHECK)
	{
		std::cout << "\t" << "CORINFO_FLG_SECURITYCHECK: Is one of the security routines that does a stackwalk (e.g. Assert, Demand)" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_NOGCCHECK)
	{
		std::cout << "\t" << "CORINFO_FLG_NOGCCHECK: This method is FCALL that has no GC check.  Don't put alone in loops" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_INTRINSIC)
	{
		std::cout << "\t" << "CORINFO_FLG_INTRINSIC: This method MAY have an intrinsic ID" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_CONSTRUCTOR)
	{
		std::cout << "\t" << "CORINFO_FLG_CONSTRUCTOR: This method is an instance or type initializer" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_AGGRESSIVE_OPT)
	{
		std::cout << "\t" << "CORINFO_FLG_AGGRESSIVE_OPT: The method may contain hot code and should be aggressively optimized if possible" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_NOSECURITYWRAP)
	{
		std::cout << "\t" << "CORINFO_FLG_NOSECURITYWRAP: The method requires no security checks" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_DONT_INLINE)
	{
		std::cout << "\t" << "CORINFO_FLG_DONT_INLINE: The method should not be inlined" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_DONT_INLINE_CALLER)
	{
		std::cout << "\t" << "CORINFO_FLG_DONT_INLINE_CALLER: The method should not be inlined, nor should its callers. It cannot be tail called" << std::endl;
	}
	if (attribs & CorInfoFlag::CORINFO_FLG_JIT_INTRINSIC)
	{
		std::cout << "\t" << "CORINFO_FLG_JIT_INTRINSIC: Method is a potential jit intrinsic; verify identity by name check" << std::endl;
	}
	std::cout << "===" << std::endl;

	DumpILToConsole(info->ILCode, info->ILCodeSize);
	compileMethod(classthis, comp, info, flags, nativeEntry, nativeSizeOfCode);
	return 1;
}

void HookJIT() {
	LoadLibraryA("mscoree.dll");
	auto p = LoadLibraryA("C:/Windows/Microsoft.NET/Framework64/v4.0.30319/clrjit.dll");
	//auto p = LoadLibraryA("C:/Windows/Microsoft.NET/Framework64/v2.0.50727/mscorjit.dll");
	
	if (auto ptrGetJit = (size_t(__stdcall*)()) GetProcAddress(p, "getJit")) {

		if (JIT* pJit = (JIT*)*((ULONG_PTR*)ptrGetJit()))
		{
			DWORD OldProtect;
			VirtualProtect(pJit, sizeof(ULONG_PTR), PAGE_READWRITE, &OldProtect);
			compileMethod = pJit->compileMethod;
			pJit->compileMethod = &my_compileMethod;
			VirtualProtect(pJit, sizeof(ULONG_PTR), OldProtect, &OldProtect);
		}
	}
}

int wmain(int argc, wchar_t* argv[]) {
	HookJIT();
	PCHAR ptrBinary; DWORD lenBinary;
	if (!readBinFile("C:/dotNet2.0_PoC_x86.exe", ptrBinary, lenBinary))
		return -1;

	printf(" --- Try to Fetch .NET Framework v2.0 ---\n");
	ICorRuntimeHost* pRuntimeHost = getCorRtHost_byVersion(L"v2.0.50727");
	pRuntimeHost = 0;

	printf("\n --- Enumerate Available CLR Runtime ---\n");
	if (!pRuntimeHost) if ((pRuntimeHost = bruteforce_CLRhost()) == 0)
		return -1;
	
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

