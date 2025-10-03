#include "types.h"


VOID _PRINT_DOS_HEADER(PIMAGE_DOS_HEADER dosHeader){
    hMapping = CreateFileMappingA(hFile, NULL, 0x04, 0, 0, NULL);
    if (!hMapping)
    {
        printf("Error Creating file map, returned with error code: %d\n", GetLastError());
    }

    mappedView = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!mappedView)
    {
        printf("Error mapping the memory view, returned with error code: %d\n", GetLastError());
    }
    dosHeader = (PIMAGE_DOS_HEADER)mappedView;
    ntHeader = (PIMAGE_NT_HEADERS)((BYTE *)mappedView + dosHeader->e_lfanew);

    printf("--------------- DOS HEADER ---------------\n");
    printf("\t0x%x\t\tPE Signature\n", ntHeader->Signature);
    printf("\t0x%x\t\tMZ Signature\n", dosHeader->e_magic);
    printf("\t0x%x\t\tBytes on last page of file\n", dosHeader->e_cblp);
    printf("\t0x%x\t\tPages in file\n", dosHeader->e_cp);
    printf("\t0x%x\t\tRelocations\n", dosHeader->e_crlc);
    printf("\t0x%x\t\tSize of header in paragraphs\n", dosHeader->e_cparhdr);
    printf("\t0x%x\t\tMinimum extra paragraphs needed\n", dosHeader->e_minalloc);
    printf("\t0x%x\t\tMaximum extra paragraphs needed\n", dosHeader->e_maxalloc);
    printf("\t0x%x\t\tInitial (relative) SS value\n", dosHeader->e_ss);
    printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
    printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
    printf("\t0x%x\t\tChecksum\n", dosHeader->e_csum);
    printf("\t0x%x\t\tInitial IP value\n", dosHeader->e_ip);
    printf("\t0x%x\t\tInitial (relative) CS value\n", dosHeader->e_cs);
    printf("\t0x%x\t\tFile address of relocation table\n", dosHeader->e_lfarlc);
    printf("\t0x%x\t\tOverlay number\n", dosHeader->e_ovno);
    printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", dosHeader->e_oemid);
    printf("\t0x%x\t\tOEM information; e_oemid specific\n", dosHeader->e_oeminfo);
    printf("\t0x%x\t\tFile address of new exe header\n", dosHeader->e_lfanew);
}