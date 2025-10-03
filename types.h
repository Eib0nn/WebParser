#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#ifdef _CPP
#include <iostream>
#endif

typedef VOID _PRINT_DOS_HEADER(
    PIMAGE_DOS_HEADER dosHeader);

typedef VOID _PRINT_NT_HEADER(
    PIMAGE_NT_HEADERS ntHeader);

typedef VOID _PRINT_FILE_HEADER(
    PIMAGE_FILE_HEADER fileHeader);

typedef VOID _PRINT_OPTIONAL_HEADER(
    PIMAGE_OPTIONAL_HEADER optHeader);

typedef VOID _PRINT_SECTIONS(
    PIMAGE_SECTION_HEADER sectionHeader,
    WORD numberOfSections);