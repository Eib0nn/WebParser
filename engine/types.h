#pragma once

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

    typedef uint8_t BYTE;
    typedef uint16_t WORD;
    typedef uint32_t DWORD;
    typedef uint64_t QWORD;

    typedef int BOOL;
#define TRUE 1
#define FALSE 0

    typedef void *LPVOID;

    // Minimal IMAGE_DOS_HEADER
    typedef struct _IMAGE_DOS_HEADER
    {
        WORD e_magic; 
        WORD e_cblp;
        WORD e_cp;
        WORD e_crlc;
        WORD e_cparhdr;
        WORD e_minalloc;
        WORD e_maxalloc;
        WORD e_ss;
        WORD e_sp;
        WORD e_csum;
        WORD e_ip;
        WORD e_cs;
        WORD e_lfarlc;
        WORD e_ovno;
        WORD e_res[4];
        WORD e_oemid;
        WORD e_oeminfo;
        WORD e_res2[10];
        int32_t e_lfanew; // offset to NT header
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

    // File header
    typedef struct _IMAGE_FILE_HEADER
    {
        WORD Machine;
        WORD NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD SizeOfOptionalHeader;
        WORD Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

    // Optional header (32-bit)
    typedef struct _IMAGE_OPTIONAL_HEADER32
    {
        WORD Magic;
        BYTE MajorLinkerVersion;
        BYTE MinorLinkerVersion;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        DWORD BaseOfData;
        DWORD ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD MajorOperatingSystemVersion;
        WORD MinorOperatingSystemVersion;
        WORD MajorImageVersion;
        WORD MinorImageVersion;
        WORD MajorSubsystemVersion;
        WORD MinorSubsystemVersion;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD Subsystem;
        WORD DllCharacteristics;
        DWORD SizeOfStackReserve;
        DWORD SizeOfStackCommit;
        DWORD SizeOfHeapReserve;
        DWORD SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
        // DataDirectory omitted - we will access DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] by offset in parsefn
    } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

    // Optional header (64-bit) - simplified
    typedef struct _IMAGE_OPTIONAL_HEADER64
    {
        WORD Magic;
        BYTE MajorLinkerVersion;
        BYTE MinorLinkerVersion;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        QWORD ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD MajorOperatingSystemVersion;
        WORD MinorOperatingSystemVersion;
        WORD MajorImageVersion;
        WORD MinorImageVersion;
        WORD MajorSubsystemVersion;
        WORD MinorSubsystemVersion;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD Subsystem;
        WORD DllCharacteristics;
        QWORD SizeOfStackReserve;
        QWORD SizeOfStackCommit;
        QWORD SizeOfHeapReserve;
        QWORD SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
    } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

    // NT headers 32 and 64
    typedef struct _IMAGE_NT_HEADERS32
    {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

    typedef struct _IMAGE_NT_HEADERS64
    {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

    // Section header
    typedef struct _IMAGE_SECTION_HEADER
    {
        BYTE Name[8];
        union
        {
            DWORD PhysicalAddress;
            DWORD VirtualSize;
        } Misc;
        DWORD VirtualAddress;
        DWORD SizeOfRawData;
        DWORD PointerToRawData;
        DWORD PointerToRelocations;
        DWORD PointerToLinenumbers;
        WORD NumberOfRelocations;
        WORD NumberOfLinenumbers;
        DWORD Characteristics;
    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

    // Import descriptor
    typedef struct _IMAGE_IMPORT_DESCRIPTOR
    {
        union
        {
            DWORD Characteristics; 
            DWORD OriginalFirstThunk;
        } DUMMYUNIONNAME;
        DWORD TimeDateStamp;
        DWORD ForwarderChain;
        DWORD Name;
        DWORD FirstThunk;
    } IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

    // Import by name
    typedef struct _IMAGE_IMPORT_BY_NAME
    {
        WORD Hint;
        char Name[1];
    } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

    // Thunk data 
    typedef struct _IMAGE_THUNK_DATA64
    {
        union
        {
            QWORD ForwarderString;
            QWORD Function;
            QWORD Ordinal;
            QWORD AddressOfData;
        } u1;
    } IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

    typedef struct _IMAGE_THUNK_DATA32
    {
        union
        {
            DWORD ForwarderString;
            DWORD Function;
            DWORD Ordinal;
            DWORD AddressOfData;
        } u1;
    } IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_SNAP_BY_ORDINAL(x) (((uintptr_t)(x) & 0x80000000u) != 0)
#define IMAGE_ORDINAL(x) ((uintptr_t)(x) & 0xffff)

    typedef enum _PE_TYPE
    {
        PE_UNKNOWN,
        PE32,
        PE64
    } PE_TYPE;

    typedef struct _DOS_LAYER
    {
        PIMAGE_DOS_HEADER Header;
        DWORD OffsetToPE;
    } DOS_LAYER;

    typedef struct _NT_LAYER
    {
        PIMAGE_NT_HEADERS32 Header; 
        PIMAGE_FILE_HEADER FileHeader;
        void *OptionalHeader; 
    } NT_LAYER;

    typedef struct _SECTION_LAYER
    {
        PIMAGE_SECTION_HEADER Header;
        WORD Count;
        DWORD OffsetToSection;
    } SECTION_LAYER;

    typedef struct _DLL_IMPORTS
    {
        PIMAGE_IMPORT_DESCRIPTOR Header;
        DWORD IDTOffset;
    } DLL_IMPORT;

    typedef struct _PE_FILE
    {
        int fd; // file descriptor
        void *MappedView;
        size_t MappedSize;
        DOS_LAYER Dos;
        NT_LAYER Nt;
        PE_TYPE Type;
        SECTION_LAYER Sections;
        DLL_IMPORT Dlls;
    } PE_FILE;

#ifdef __cplusplus
}
#endif