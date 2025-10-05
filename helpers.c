#include "types.h"

BOOL LoadPEFile(PE_FILE *pe, const char *filename)
{
    pe->hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (pe->hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileA failed (%d)\n", GetLastError());
        return FALSE;
    }

    pe->hMapping = CreateFileMappingA(pe->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!pe->hMapping)
    {
        printf("CreateFileMappingA failed (%d)\n", GetLastError());
        CloseHandle(pe->hFile);
        return FALSE;
    }

    pe->MappedView = MapViewOfFile(pe->hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pe->MappedView)
    {
        printf("MapViewOfFile failed (%d)\n", GetLastError());
        CloseHandle(pe->hMapping);
        CloseHandle(pe->hFile);
        return FALSE;
    }

    // apontando os headers ** (_PE_FILE)pe->(_DOS_LAYER)Dos.Header = handle da memoria do bin (MappedView)
    pe->Dos.Header = (PIMAGE_DOS_HEADER)pe->MappedView;
    pe->Dos.OffsetToPE = pe->Dos.Header->e_lfanew;

    // cast bizarro por que a merda do windows tem 2 structs pros NtHeaders XDDD (PIMAGE_NT_HEADERS32 // PIMAGE_NT_HEADERS64)
    pe->Nt.Header = (PIMAGE_NT_HEADERS)((BYTE *)pe->MappedView + pe->Dos.OffsetToPE);

    WORD magicNumber = pe->Nt.Header->OptionalHeader.Magic;
    if (magicNumber == 0x10B)
        pe->Type = PE32;
    else if (magicNumber == 0x20B)
        pe->Type = PE64;
    else
        pe->Type = PE_UNKNOWN;

    return TRUE;
}

VOID ParseDOSLayer(PE_FILE *pe)
{
    PIMAGE_DOS_HEADER dos = pe->Dos.Header;

    printf("--------------- DOS HEADER ---------------\n");
    printf("\t0x%x\t\tMZ Signature\n", dos->e_magic);
    printf("\t0x%x\t\tBytes on last page of file\n", dos->e_cblp);
    printf("\t0x%x\t\tPages in file\n", dos->e_cp);
    printf("\t0x%x\t\tRelocations\n", dos->e_crlc);
    printf("\t0x%x\t\tSize of header in paragraphs\n", dos->e_cparhdr);
    printf("\t0x%x\t\tMinimum extra paragraphs needed\n", dos->e_minalloc);
    printf("\t0x%x\t\tMaximum extra paragraphs needed\n", dos->e_maxalloc);
    printf("\t0x%x\t\tInitial (relative) SS value\n", dos->e_ss);
    printf("\t0x%x\t\tInitial SP value\n", dos->e_sp);
    printf("\t0x%x\t\tChecksum\n", dos->e_csum);
    printf("\t0x%x\t\tInitial IP value\n", dos->e_ip);
    printf("\t0x%x\t\tInitial (relative) CS value\n", dos->e_cs);
    printf("\t0x%x\t\tFile address of relocation table\n", dos->e_lfarlc);
    printf("\t0x%x\t\tOverlay number\n", dos->e_ovno);
    printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", dos->e_oemid);
    printf("\t0x%x\t\tOEM information; e_oemid specific\n", dos->e_oeminfo);
    printf("\t0x%x\t\tFile address of new exe header\n", dos->e_lfanew);
}

VOID ParseNTLayer(PE_FILE *pe)
{
    printf("--------------- NT HEADER ---------------\n");

    WORD magic = pe->Nt.Header->OptionalHeader.Magic;
    printf("Magic: 0x%x\n", magic);

    // PE32 OFFSET == 28
    if (magic == 0x10B){ 
        PIMAGE_NT_HEADERS32 ntHeader32 = (PIMAGE_NT_HEADERS32)((BYTE *)pe->MappedView + pe->Dos.Header->e_lfanew);

        printf("PE Signature: 0x%x\n", ntHeader32->Signature);
        printf("Machine: 0x%x\n", ntHeader32->FileHeader.Machine);
        printf("Number of Sections: %d\n", ntHeader32->FileHeader.NumberOfSections);
        printf("Entry Point RVA: 0x%x\n", ntHeader32->OptionalHeader.AddressOfEntryPoint);
        printf("Image Base: 0x%x\n", ntHeader32->OptionalHeader.ImageBase);
    }

    // PE32+ OFFSET == 24 pros optHeaders e images
    else if (magic == 0x20B){ 
        PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)((BYTE *)pe->MappedView + pe->Dos.Header->e_lfanew);

        printf("PE Signature: 0x%x\n", ntHeader64->Signature);
        printf("Machine: 0x%x\n", ntHeader64->FileHeader.Machine);
        printf("Number of Sections: %d\n", ntHeader64->FileHeader.NumberOfSections);
        printf("Entry Point RVA: 0x%x\n", ntHeader64->OptionalHeader.AddressOfEntryPoint);
        printf("Image Base: 0x%llx\n", ntHeader64->OptionalHeader.ImageBase);
    }
    else
    {
        printf("Unknown PE type (Magic = 0x%x)\n", magic);
    }
}