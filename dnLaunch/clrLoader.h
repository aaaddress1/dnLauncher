#include <mscoree.h>
#include <metahost.h>
#pragma comment(lib, "MSCorEE.lib")

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import "mscorlib.tlb" auto_rename
using namespace mscorlib;

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
bool bruteforce_CLRhost(LPWSTR frameworkName, LPWSTR frameworkDir) {
	ICLRMetaHost* metaHost = NULL;
	IEnumUnknown* runtime = NULL;
	ICLRRuntimeInfo* runtimeInfo = nullptr;
	DWORD bytes;
	if (CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost) != S_OK) {
		printf("[x] Error: CLRCreateInstance(..)\n");
		return false;
	}

	if (metaHost->EnumerateInstalledRuntimes(&runtime) != S_OK) {
		printf("[x] Error: EnumerateInstalledRuntimes(..)\n");
		return false;
	}
	bool bFound = false;
	IUnknown* enumRuntime = nullptr;
	// Enumerate through runtimes and show supported frameworks
	while (runtime->Next(1, &enumRuntime, 0) == S_OK)
		if (enumRuntime->QueryInterface<ICLRRuntimeInfo>(&runtimeInfo) == S_OK)
			if (runtimeInfo != NULL) {
				memset(frameworkDir, 0, MAX_PATH); bytes = MAX_PATH;
				runtimeInfo->GetRuntimeDirectory(frameworkDir, &bytes);

				memset(frameworkName, 0, MAX_PATH); bytes = MAX_PATH;
				runtimeInfo->GetVersionString(frameworkName, &bytes);
				wprintf(L"[*] Found %s @ %s\n", frameworkName, frameworkDir);
				bFound = true;
			}

	return bFound;
}