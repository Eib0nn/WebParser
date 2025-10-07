#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#ifdef __cplusplus
#include <iostream>
#endif

typedef enum _PE_TYPE{
    PE_UNKNOWN,
    PE32,
    PE64
}PE_TYPE;

typedef struct _DOS_LAYER{
    PIMAGE_DOS_HEADER Header;
    DWORD OffsetToPE; // = Header->e_lfanew | offset do DOS 16-bit
} DOS_LAYER;

typedef struct _NT_LAYER{
    PIMAGE_NT_HEADERS Header;
    PIMAGE_FILE_HEADER FileHeader;
    PIMAGE_OPTIONAL_HEADER OptionalHeader;
} NT_LAYER;

typedef struct _SECTION_LAYER{
    PIMAGE_SECTION_HEADER Header;
    WORD Count;
    DWORD OffsetToSection;
}SECTION_LAYER;

typedef struct _DLL_IMPORTS{
    PIMAGE_IMPORT_DESCRIPTOR Header;
    DWORD IDTOffset;
    DWORD thunk;
    PIMAGE_THUNK_DATA TD;
}DLL_IMPORT;

typedef struct _PE_FILE{
    HANDLE hFile;
    HANDLE hMapping;
    LPVOID MappedView;
    DOS_LAYER Dos;
    NT_LAYER Nt;
    PE_TYPE Type;
    SECTION_LAYER Sections;
    DLL_IMPORT Dlls;
} PE_FILE;

#ifdef __cplusplus
extern "C"{
#endif
typedef BOOL _LOAD_PE_FILE(
    PE_FILE *pe, const char *filename
);

typedef VOID _UNLOAD_PE_FILE(
    PE_FILE *pe);

typedef VOID _PARSE_DOS_LAYER(
    PE_FILE *pe);

typedef VOID _PARSE_NT_LAYER(
    PE_FILE *pe
);

typedef VOID _PARSE_SECTIONS(
    PE_FILE *pe
);

typedef VOID _PARSE_DLL_IMPORTS(
    PE_FILE *pe
);

typedef VOID _RVA_TO_FILE_OFFSET(
    PE_FILE *pe, 
    DWORD rva
);

BOOL LoadPEFile(PE_FILE *pe, const char* file);
VOID UnloadPEFile(PE_FILE *pe);
VOID ParseDOSLayer(PE_FILE *pe);
VOID ParseNTLayer(PE_FILE *pe);
VOID ParseSections(PE_FILE *pe);
VOID ParseDLL(PE_FILE *pe);
DWORD RvaToFileOffset(PE_FILE *pe, DWORD rva);

#ifdef __cplusplus
}
#endif