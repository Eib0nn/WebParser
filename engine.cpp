#define _CPP
#include "types.h"

int main(){
    DWORD   dAccess =   GENERIC_ALL;
    DWORD   dwSM    =   FILE_SHARE_READ;
    DWORD   dwCD    =   OPEN_EXISTING;
    DWORD   dwFAA   =   FILE_ATTRIBUTE_NORMAL;
    DWORD   bytes   =   NULL;
    DWORD   filesize    =   NULL;
    LPVOID  filedata    =   NULL;
    HANDLE  hMapping;
    LPVOID  mappedView;
    HANDLE  hFile;
    PIMAGE_DOS_HEADER   dosHeader   =   {};
    PIMAGE_NT_HEADERS   ntHeader    =   {};

    // Abrir arquivo como bin
    hFile = CreateFileA("helloworld.exe", dAccess, dwSM, 0, dwCD, dwFAA, 0);
    if (!hFile){
        printf("Couldnt read the file, returned with error code: %d\n", GetLastError());
        return 0;
    }

    // Ler as structs do DOS_HEADER (1a layer do PE)
    /*
    filesize = GetFileSize(hFile, NULL);
    filedata = HeapAlloc(GetProcessHeap(), 0 , filesize);

    ReadFile(hFile, filedata,filesize, &bytes, NULL);
    */

}