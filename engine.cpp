#include "types.h"
#include <nlohmann/json.hpp>

int main()
{
    PE_FILE pe;
    const char* filename = "helloworld.exe";
    _LOAD_PE_FILE* loadFile = &LoadPEFile;
    _PARSE_DOS_LAYER *ParseDos = &ParseDOSLayer;
    _PARSE_NT_LAYER *ParseNT = &ParseNTLayer;
    _PARSE_SECTIONS* ParseSec = &ParseSections;
    _PARSE_DLL_IMPORTS* ParseDll = &ParseDLL;
    BOOL hPE = loadFile(&pe, filename);
    ParseDos(&pe);
    ParseNT(&pe);
    ParseSec(&pe);
    ParseDll(&pe);
        
    /*
    UnmapViewOfFile(mappedView);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    */
}
