#include <windows.h>
#include <amsi.h>
#include <initguid.h>

//cl.exe /LD monitor/amsi.c /Fe:LoukoumAMSI.dll /link /DEF:monitor/amsi.def advapi32.lib
//regsvr32 /u C:\Antivirus_loukoum\LoukoumAMSI.dll
//regsvr32 C:\Antivirus_loukoum\LoukoumAMSI.dll


DEFINE_GUID(IID_IAntimalwareProvider, 0xB2CC8FF9, 0xC10E, 0x4C31, 0xB1, 0xC0, 0x1F, 0xB9, 0x00, 0x5C, 0x5C, 0xFA);

typedef struct LoukoumProvider LoukoumProvider;

// La vtable : table de tous les pointeurs de fonctions de l'interface
typedef struct {
    // 3 méthodes IUnknown (héritées par toutes les interfaces COM)
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(LoukoumProvider *this, REFIID riid, void **ppv);
    ULONG   (STDMETHODCALLTYPE *AddRef)(LoukoumProvider *this);
    ULONG   (STDMETHODCALLTYPE *Release)(LoukoumProvider *this);
    
    // 3 méthodes IAntimalwareProvider
    HRESULT (STDMETHODCALLTYPE *Scan)(LoukoumProvider *this, IAmsiStream *stream, AMSI_RESULT *result);
    void    (STDMETHODCALLTYPE *CloseSession)(LoukoumProvider *this, ULONGLONG session);
    HRESULT (STDMETHODCALLTYPE *DisplayName)(LoukoumProvider *this, LPWSTR *displayName);
    HRESULT (STDMETHODCALLTYPE *Notify)(LoukoumProvider *this, LPCWSTR contentName, LPCWSTR appName, AMSI_RESULT *pResult);


} LoukoumProviderVtbl;

// La struct de l'objet : pointeur vers vtable + données
struct LoukoumProvider {
    LoukoumProviderVtbl *lpVtbl;  // pointeur vers la vtable
    LONG refCount;                 // compteur de références COM
};

// --- IUnknown methods ---
DEFINE_GUID(IID_IAntimalwareProvider2,
    0x7c1e6570, 0x3f73, 0x4e0f, 0x8a, 0xd4, 0x98, 0xb9, 0x4c, 0xd3, 0x29, 0x0f);

static HRESULT STDMETHODCALLTYPE Loukoum_QueryInterface(LoukoumProvider *this, REFIID riid, void **ppv) {
    if (IsEqualIID(riid, &IID_IUnknown) 
        || IsEqualIID(riid, &IID_IAntimalwareProvider)
        || IsEqualIID(riid, &IID_IAntimalwareProvider2)) {
        *ppv = this;
        this->lpVtbl->AddRef(this);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Loukoum_AddRef(LoukoumProvider *this) {
    return InterlockedIncrement(&this->refCount);
}

static ULONG STDMETHODCALLTYPE Loukoum_Release(LoukoumProvider *this) {
    LONG count = InterlockedDecrement(&this->refCount);
    if (count == 0) {
        HeapFree(GetProcessHeap(), 0, this);
    }
    return count;
}


// --- IAntimalwareProvider methods ---

static HRESULT STDMETHODCALLTYPE Loukoum_Scan(LoukoumProvider *this, IAmsiStream *stream, AMSI_RESULT *result) {
    // Appelée par Windows quand une app veut scanner du contenu
    // Pour l'instant on retourne CLEAN systématiquement
    OutputDebugStringA("LoukoumAV: Scan appele !\n");
    *result = AMSI_RESULT_CLEAN;
    return S_OK;
}

static void STDMETHODCALLTYPE Loukoum_CloseSession(LoukoumProvider *this, ULONGLONG session) {
    // Nettoie une session de scan — rien à faire pour l'instant
}

static HRESULT STDMETHODCALLTYPE Loukoum_DisplayName(LoukoumProvider *this, LPWSTR *displayName) {
    // Retourne le nom de notre AV
    static WCHAR name[] = L"Loukoum AV";
    *displayName = name;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Loukoum_Notify(LoukoumProvider *this, LPCWSTR contentName, LPCWSTR appName, AMSI_RESULT *pResult) {
    OutputDebugStringA("LoukoumAV: Notify appele!\n");
    *pResult = AMSI_RESULT_CLEAN;
    return S_OK;
}

// La vtable — une seule instance partagée par tous les objets
static LoukoumProviderVtbl g_vtbl = {
    Loukoum_QueryInterface,
    Loukoum_AddRef,
    Loukoum_Release,
    Loukoum_Scan,
    Loukoum_CloseSession,
    Loukoum_DisplayName,
    Loukoum_Notify
};

// Factory : crée une nouvelle instance du provider
static HRESULT CreateLoukoumProvider(REFIID riid, void **ppv) {
    LoukoumProvider *provider = HeapAlloc(GetProcessHeap(), 0, sizeof(LoukoumProvider));
    if (!provider) return E_OUTOFMEMORY;
    
    provider->lpVtbl = &g_vtbl;
    provider->refCount = 1;
    
    HRESULT hr = provider->lpVtbl->QueryInterface(provider, riid, ppv);
    provider->lpVtbl->Release(provider);
    return hr;
}

DEFINE_GUID(CLSID_LoukoumProvider, 
    0x7727efb5, 0xcaae, 0x4326, 0xa0, 0xaa, 0x3c, 0x80, 0xb1, 0xb4, 0xd2, 0xb7);

// Class Factory 
typedef struct {
    IClassFactoryVtbl *lpVtbl;
    LONG refCount;
} LoukoumFactory;

static HRESULT STDMETHODCALLTYPE Factory_QueryInterface(IClassFactory *this, REFIID riid, void **ppv) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory)) {
        *ppv = this;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Factory_AddRef(IClassFactory *this) { return 1; }
static ULONG STDMETHODCALLTYPE Factory_Release(IClassFactory *this) { return 1; }

static HRESULT STDMETHODCALLTYPE Factory_CreateInstance(IClassFactory *this, IUnknown *outer, REFIID riid, void **ppv) {
    if (outer) return CLASS_E_NOAGGREGATION;
    return CreateLoukoumProvider(riid, ppv);
}

static HRESULT STDMETHODCALLTYPE Factory_LockServer(IClassFactory *this, BOOL lock) { return S_OK; }

static IClassFactoryVtbl g_factoryVtbl = {
    Factory_QueryInterface,
    Factory_AddRef,
    Factory_Release,
    Factory_CreateInstance,
    Factory_LockServer
};

static LoukoumFactory g_factory = { &g_factoryVtbl, 1 };

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void **ppv) {
    if (IsEqualCLSID(clsid, &CLSID_LoukoumProvider)) {
        return g_factory.lpVtbl->QueryInterface((IClassFactory*)&g_factory, riid, ppv);
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllCanUnloadNow(void) {
    return S_FALSE;
}

// --- Registration ---

static HKEY CreateKey(HKEY root, const char *path) {
    HKEY key;
    RegCreateKeyExA(root, path, 0, NULL, 0, KEY_WRITE, NULL, &key, NULL);
    return key;
}

HRESULT WINAPI DllRegisterServer(void) {
    char dllPath[MAX_PATH];
    HMODULE hMod;
    
    // Récupère le chemin de la DLL courante
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)DllRegisterServer, &hMod);
    GetModuleFileNameA(hMod, dllPath, MAX_PATH);
    
    // Clé 1 : CLSID -> chemin DLL
    HKEY key = CreateKey(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Classes\\CLSID\\{7727efb5-caae-4326-a0aa-3c80b1b4d2b7}\\InprocServer32");
    RegSetValueExA(key, NULL, 0, REG_SZ, (BYTE*)dllPath, (DWORD)strlen(dllPath) + 1);
    RegSetValueExA(key, "ThreadingModel", 0, REG_SZ, (BYTE*)"Both", 5);
    RegCloseKey(key);
    
    // Clé 2 : AMSI Provider
    key = CreateKey(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\AMSI\\Providers\\{7727efb5-caae-4326-a0aa-3c80b1b4d2b7}");
    RegSetValueExA(key, NULL, 0, REG_SZ, (BYTE*)"Loukoum AV", 11);
    RegCloseKey(key);
    
    return S_OK;
}

HRESULT WINAPI DllUnregisterServer(void) {
    RegDeleteTreeA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Classes\\CLSID\\{7727efb5-caae-4326-a0aa-3c80b1b4d2b7}");
    RegDeleteTreeA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\AMSI\\Providers\\{7727efb5-caae-4326-a0aa-3c80b1b4d2b7}");
    return S_OK;
}