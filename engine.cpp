#include "types.h"

int main()
{
    PE_FILE pe;
    const char* filename = "helloworld.exe";
    _LOAD_PE_FILE* loadFile = &LoadPEFile;
    BOOL hPE = loadFile(&pe, filename);
    _PARSE_DOS_LAYER* ParseDos = &ParseDOSLayer;
    ParseDos(&pe);
    /*
    UnmapViewOfFile(mappedView);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    */
}
