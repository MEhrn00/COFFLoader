/*
 * COFF Loader Project
 * -------------------
 * This is a re-implementation of a COFF loader, with a BOF compatibility layer
 * it's meant to provide functional example of loading a COFF file in memory
 * and maybe be useful.
 */
#include <COFFLoader/COFFLoader.h>

#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <windows.h>

 /* Enable or disable debug output if testing or adding new relocation types */
#ifdef DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

/* Defining symbols for the OS version, will try to define anything that is
 * different between the arch versions by specifying them here. */
#if defined(__x86_64__) || defined(_WIN64)
#define PREPENDSYMBOLVALUE "__imp_"
#else
#define PREPENDSYMBOLVALUE "__imp__"
#endif

#define DEFAULTPROCESSNAME "rundll32.exe"
#ifdef _WIN64
#define X86PATH "SysWOW64"
#define X64PATH "System32"
#else
#define X86PATH "System32"
#define X64PATH "sysnative"
#endif


#define COFFLOADER_RETURN_VAL_IF(expr, val, fmt, ...) if ((expr)) { DEBUG_PRINT(fmt, ##__VA_ARGS__); return val; }


#pragma pack(push, 1)

/* sizeof 20 */
typedef struct coff_file_header {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} coff_file_header_t;

/* AMD64  should always be here */
#define MACHINETYPE_AMD64 0x8664

/* Size of 40 */
typedef struct coff_sect {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} coff_sect_t;


typedef struct coff_reloc {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} coff_reloc_t;

typedef struct coff_sym {
    union {
        char Name[8];
        uint32_t value[2];
    } first;
    uint32_t Value;
    uint16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;

} coff_sym_t;

#pragma pack(pop)

typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;

typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

static void    BeaconDataParse(datap * parser, char * buffer, int size);
static int     BeaconDataInt(datap * parser);
static short   BeaconDataShort(datap * parser);
static int     BeaconDataLength(datap * parser);
static char *  BeaconDataExtract(datap * parser, int * size);
static void    BeaconFormatAlloc(formatp * format, int maxsz);
static void    BeaconFormatReset(formatp * format);
static void    BeaconFormatFree(formatp * format);
static void    BeaconFormatAppend(formatp * format, char * text, int len);
static void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
static char *  BeaconFormatToString(formatp * format, int * size);
static void    BeaconFormatInt(formatp * format, int value);
static void   BeaconPrintf(int type, char * fmt, ...);
static void   BeaconOutput(int type, char * data, int len);

/* Token Functions */
static BOOL   BeaconUseToken(HANDLE token);
static void   BeaconRevertToken();
static BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
static void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
static BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo);
static void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
static void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
static void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
static BOOL   toWideChar(char * src, wchar_t * dst, int max);
static uint32_t swap_endianess(uint32_t indata);

 /* Data Parsing */
static unsigned char* InternalFunctions[30][2] = {
    {(unsigned char*)"BeaconDataParse", (unsigned char*)BeaconDataParse},
    {(unsigned char*)"BeaconDataInt", (unsigned char*)BeaconDataInt},
    {(unsigned char*)"BeaconDataShort", (unsigned char*)BeaconDataShort},
    {(unsigned char*)"BeaconDataLength", (unsigned char*)BeaconDataLength},
    {(unsigned char*)"BeaconDataExtract", (unsigned char*)BeaconDataExtract},
    {(unsigned char*)"BeaconFormatAlloc", (unsigned char*)BeaconFormatAlloc},
    {(unsigned char*)"BeaconFormatReset", (unsigned char*)BeaconFormatReset},
    {(unsigned char*)"BeaconFormatFree", (unsigned char*)BeaconFormatFree},
    {(unsigned char*)"BeaconFormatAppend", (unsigned char*)BeaconFormatAppend},
    {(unsigned char*)"BeaconFormatPrintf", (unsigned char*)BeaconFormatPrintf},
    {(unsigned char*)"BeaconFormatToString", (unsigned char*)BeaconFormatToString},
    {(unsigned char*)"BeaconFormatInt", (unsigned char*)BeaconFormatInt},
    {(unsigned char*)"BeaconPrintf", (unsigned char*)BeaconPrintf},
    {(unsigned char*)"BeaconOutput", (unsigned char*)BeaconOutput},
    {(unsigned char*)"BeaconUseToken", (unsigned char*)BeaconUseToken},
    {(unsigned char*)"BeaconRevertToken", (unsigned char*)BeaconRevertToken},
    {(unsigned char*)"BeaconIsAdmin", (unsigned char*)BeaconIsAdmin},
    {(unsigned char*)"BeaconGetSpawnTo", (unsigned char*)BeaconGetSpawnTo},
    {(unsigned char*)"BeaconSpawnTemporaryProcess", (unsigned char*)BeaconSpawnTemporaryProcess},
    {(unsigned char*)"BeaconInjectProcess", (unsigned char*)BeaconInjectProcess},
    {(unsigned char*)"BeaconInjectTemporaryProcess", (unsigned char*)BeaconInjectTemporaryProcess},
    {(unsigned char*)"BeaconCleanupProcess", (unsigned char*)BeaconCleanupProcess},
    {(unsigned char*)"toWideChar", (unsigned char*)toWideChar},
    {(unsigned char*)"LoadLibraryA", (unsigned char*)LoadLibraryA},
    {(unsigned char*)"GetProcAddress", (unsigned char*)GetProcAddress},
    {(unsigned char*)"GetModuleHandleA", (unsigned char*)GetModuleHandleA},
    {(unsigned char*)"FreeLibrary", (unsigned char*)FreeLibrary},
    {(unsigned char*)"__C_specific_handler", NULL}
};

static char* beacon_compatibility_output = NULL;
static int beacon_compatibility_size = 0;
static int beacon_compatibility_offset = 0;

uint32_t swap_endianess(uint32_t indata) {
    uint32_t testint = 0xaabbccdd;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL || buffer == NULL) {
        return;
    }

    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
    return;
}

int BeaconDataInt(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    int32_t fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    int16_t retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

int BeaconDataLength(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
    if (parser == NULL) {
        return NULL;
    }

    uint32_t length = 0;
    char* outdata = NULL;
    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }
    memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }
    parser->length -= 4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }
    return outdata;
}

/* format API */

void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) {
        return;
    }

    format->original = calloc(maxsz, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

void BeaconFormatReset(formatp* format) {
    if (format == NULL) {
        return;
    }

    memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = format->size;
    return;
}

void BeaconFormatFree(formatp* format) {
    if (format == NULL) {
        return;
    }
    if (format->original) {
        free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
    if (format == NULL || text == NULL) {
        return;
    }

    memcpy(format->buffer, text, len);
    format->buffer += len;
    format->length += len;
    return;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    if (format == NULL || fmt == NULL) {
        return;
    }

    /*Take format string, and sprintf it into here*/
    va_list args;
    int length = 0;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (format->length + length > format->size) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(format->buffer, length, fmt, args);
    va_end(args);
    format->length += length;
    format->buffer += length;
    return;
}


char* BeaconFormatToString(formatp* format, int* size) {
    if (format == NULL || size == NULL) {
        return NULL;
    }

    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    if (format == NULL) {
        return;
    }

    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
    memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

/* Main output functions */

void BeaconPrintf(int type, char* fmt, ...) {
    if (fmt == NULL) {
        return;
    }

    /* Change to maintain internal buffer, and return after done running. */
    int length = 0;
    char* tempptr = NULL;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    tempptr = realloc(beacon_compatibility_output, beacon_compatibility_size + length + 1);
    if (tempptr == NULL) {
        return;
    }
    beacon_compatibility_output = tempptr;
    memset(beacon_compatibility_output + beacon_compatibility_offset, 0, length + 1);
    va_start(args, fmt);
    length = vsnprintf(beacon_compatibility_output + beacon_compatibility_offset, length +1, fmt, args);
    beacon_compatibility_size += length;
    beacon_compatibility_offset += length;
    va_end(args);
    return;
}

void BeaconOutput(int type, char* data, int len) {
    if (data == NULL) {
        return;
    }

    char* tempptr = NULL;
    tempptr = realloc(beacon_compatibility_output, beacon_compatibility_size + len + 1);
    beacon_compatibility_output = tempptr;
    if (tempptr == NULL) {
        return;
    }
    memset(beacon_compatibility_output + beacon_compatibility_offset, 0, len + 1);
    memcpy(beacon_compatibility_output + beacon_compatibility_offset, data, len);
    beacon_compatibility_size += len;
    beacon_compatibility_offset += len;
    return;
}

/* Token Functions */

BOOL BeaconUseToken(HANDLE token) {
    /* Probably needs to handle DuplicateTokenEx too */
    SetThreadToken(NULL, token);
    return TRUE;
}

void BeaconRevertToken(void) {
    if (!RevertToSelf()) {
#ifdef DEBUG
        printf("RevertToSelf Failed!\n");
#endif
    }
    return;
}

BOOL BeaconIsAdmin(void) {
    /* Leaving this to be implemented by people needing it */
#ifdef DEBUG
    printf("BeaconIsAdmin Called\n");
#endif
    return FALSE;
}

/* Injection/spawning related stuffs
 *
 * These functions are basic place holders, and if implemented into something
 * real should be just calling internal functions for your tools. */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    char* tempBufferPath = NULL;
    if (buffer == NULL) {
        return;
    }
    if (x86) {
        tempBufferPath = "C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME;
    }
    else {
        tempBufferPath = "C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME;
    }

    if ((int)strlen(tempBufferPath) > length) {
        return;
    }
    memcpy(buffer, tempBufferPath, strlen(tempBufferPath));
    return;
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo) {
    BOOL bSuccess = FALSE;
    if (x86) {
        bSuccess = CreateProcessA(NULL, (char*)"C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    }
    else {
        bSuccess = CreateProcessA(NULL, (char*)"C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    }
    return bSuccess;
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char * arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
    if (pInfo != NULL) {
        (void)CloseHandle(pInfo->hThread);
        (void)CloseHandle(pInfo->hProcess);
    }
    return;
}

BOOL toWideChar(char* src, wchar_t* dst, int max) {
    if (max < sizeof(wchar_t))
        return FALSE;
    return MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, src, -1, dst, max / sizeof(wchar_t));
}


static BOOL starts_with(const char* string, const char* substring) {
    return strncmp(string, substring, strlen(substring)) == 0;
}

/* Helper function to process a symbol string, determine what function and
 * library its from, and return the right function pointer. Will need to
 * implement in the loading of the beacon internal functions, or any other
 * internal functions you want to have available. */
static void* process_symbol(char* symbolstring) {
    void* functionaddress = NULL;
    char localcopy[1024] = { 0 };
    char* locallib = NULL;
    char* localfunc = NULL;
#if defined(_WIN32)    
    int tempcounter = 0;
    HMODULE llHandle = NULL;
#endif

    strncpy(localcopy, symbolstring, sizeof(localcopy) - 1);
    if (starts_with(symbolstring, PREPENDSYMBOLVALUE"Beacon") || starts_with(symbolstring, PREPENDSYMBOLVALUE"toWideChar") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetProcAddress") || starts_with(symbolstring, PREPENDSYMBOLVALUE"LoadLibraryA") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetModuleHandleA") || starts_with(symbolstring, PREPENDSYMBOLVALUE"FreeLibrary") ||
        starts_with(symbolstring, "__C_specific_handler")) {
        if(strcmp(symbolstring, "__C_specific_handler") == 0)
        {
            localfunc = symbolstring;
            return InternalFunctions[29][1];
        }
        else
        {
            localfunc = symbolstring + strlen(PREPENDSYMBOLVALUE);
        }
        DEBUG_PRINT("\t\tInternalFunction: %s\n", localfunc);
        /* TODO: Get internal symbol here and set to functionaddress, then
         * return the pointer to the internal function*/
#if defined(_WIN32)
        for (tempcounter = 0; tempcounter < 30; tempcounter++) {
            if (InternalFunctions[tempcounter][0] != NULL) {
                if (starts_with(localfunc, (char*)(InternalFunctions[tempcounter][0]))) {
                    functionaddress = (void*)InternalFunctions[tempcounter][1];
                    return functionaddress;
                }
            }
        }
#endif
    }
    else if (strncmp(symbolstring, PREPENDSYMBOLVALUE, strlen(PREPENDSYMBOLVALUE)) == 0) {
        DEBUG_PRINT("\t\tYep its an external symbol\n");
        locallib = localcopy + strlen(PREPENDSYMBOLVALUE);

        locallib = strtok(locallib, "$");
        localfunc = strtok(NULL, "$");
        DEBUG_PRINT("\t\tLibrary: %s\n", locallib);
        localfunc = strtok(localfunc, "@");
        DEBUG_PRINT("\t\tFunction: %s\n", localfunc);
        /* Resolve the symbols here, and set the functionpointervalue */
#if defined(_WIN32)
        llHandle = LoadLibraryA(locallib);
        DEBUG_PRINT("\t\tHandle: 0x%lx\n", llHandle);
        functionaddress = GetProcAddress(llHandle, localfunc);
        DEBUG_PRINT("\t\tProcAddress: 0x%p\n", functionaddress);
#endif
    }
    return functionaddress;
}

static bool coff_symbol_is_defined(struct coff_sym *symbol) {
    return symbol->SectionNumber > 0;
}

static bool coff_symbol_is_external(struct coff_sym *symbol) {
    return symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL
        || symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF;
}

/* Just a generic runner for testing, this is pretty much just a reference
 * implementation, return values will need to be checked, more relocation
 * types need to be handled, and needs to have different arguments for use
 * in any agent. */
int COFFLoader_RunCOFF(char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize) {
    coff_sect_t *coff_sect_ptr = NULL;
    coff_reloc_t *coff_reloc_ptr = NULL;
    int retcode = 0;
    int counter = 0;
    int reloccount = 0;
    unsigned int tempcounter = 0;
    char *symbol_name = NULL;

    COFFLOADER_RETURN_VAL_IF(functionname == NULL, 1, "Function name is NULL\n");
    COFFLOADER_RETURN_VAL_IF(coff_data == NULL, 1, "Can't execute NULL\n");
    COFFLOADER_RETURN_VAL_IF(filesize == 0, 1, "COFF file size is 0\n");
    COFFLOADER_RETURN_VAL_IF(filesize < sizeof(struct coff_file_header), 1,
            "COFF file size too small for a COFF file header\n");

    struct coff_file_header *coff_header_ptr = (struct coff_file_header*)coff_data;

    COFFLOADER_RETURN_VAL_IF(coff_header_ptr->PointerToSymbolTable < sizeof(struct coff_file_header),
            1, "COFF symbol table offset is inside the file header\n");
    COFFLOADER_RETURN_VAL_IF(filesize < coff_header_ptr->PointerToSymbolTable, 1,
            "COFF symbol table offset exceeds file size\n");

    // Byte index of the strtab/end of symtab
    size_t coff_strtab_index =
        coff_header_ptr->PointerToSymbolTable + coff_header_ptr->NumberOfSymbols * sizeof(struct coff_sym);

    COFFLOADER_RETURN_VAL_IF(filesize < coff_strtab_index, 1, "COFF symbol table exceeds COFF file size\n");
    COFFLOADER_RETURN_VAL_IF(filesize < coff_strtab_index + sizeof(uint32_t), 1,
            "COFF string table offset exceeds COFF file size\n");

    uint32_t coff_strtab_size = *(uint32_t*)(coff_data + coff_strtab_index);

    COFFLOADER_RETURN_VAL_IF(filesize < coff_strtab_index + coff_strtab_size, 1,
            "COFF string table exceeds COFF file size\n");
    COFFLOADER_RETURN_VAL_IF(filesize != coff_strtab_index + coff_strtab_size, 1,
            "COFF file contains extraneous data\n");

    struct coff_sym *coff_sym_ptr = (struct coff_sym*)(coff_data + coff_header_ptr->PointerToSymbolTable);

#ifdef _WIN32
    void* funcptrlocation = NULL;
    size_t offsetvalue = 0;
#endif
    char* entryfuncname = functionname;
#if defined(__x86_64__) || defined(_WIN64)
#ifdef _WIN32
    uint64_t longoffsetvalue = 0;
#endif
#else
    /* Set the input function name to match the 32 bit version */
    entryfuncname = calloc(strlen(functionname) + 2, 1);
    if (entryfuncname == NULL) {
        return 1;
    }
    (void)sprintf(entryfuncname, "_%s", functionname);
#endif
    HMODULE kern = GetModuleHandleA("kernel32.dll");
    InternalFunctions[29][1] = (unsigned char *) GetProcAddress(kern, "__C_specific_handler");
    DEBUG_PRINT("found address of %x\n", InternalFunctions[29][1]);
#ifdef _WIN32
    /* NOTE: I just picked a size, look to see what is max/normal. */
    char** sectionMapping = NULL;
#ifdef DEBUG
    int *sectionSize = NULL;
#endif
    void(*foo)(char* in, unsigned long datalen);
    void **functionMapping = NULL;
    int functionMappingCount = 0;
    int relocationCount = 0;
#endif
    /* Buffer to hold the symbol short name if the symbol has no trailing NULL byte */
    char symbol_shortname_buffer[9] = {0};

    DEBUG_PRINT("Machine 0x%X\n", coff_header_ptr->Machine);
    DEBUG_PRINT("Number of sections: %d\n", coff_header_ptr->NumberOfSections);
    DEBUG_PRINT("TimeDateStamp : %X\n", coff_header_ptr->TimeDateStamp);
    DEBUG_PRINT("PointerToSymbolTable : 0x%X\n", coff_header_ptr->PointerToSymbolTable);
    DEBUG_PRINT("NumberOfSymbols: %u\n", coff_header_ptr->NumberOfSymbols);
    DEBUG_PRINT("OptionalHeaderSize: %d\n", coff_header_ptr->SizeOfOptionalHeader);
    DEBUG_PRINT("Characteristics: %d\n", coff_header_ptr->Characteristics);
    DEBUG_PRINT("\n");
    /* Actually allocate an array to keep track of the sections */
    sectionMapping = (char**)calloc(sizeof(char*)*(coff_header_ptr->NumberOfSections+1), 1);
#ifdef DEBUG
    sectionSize = (int*)calloc(sizeof(int)*(coff_header_ptr->NumberOfSections+1), 1);
#endif
    if (sectionMapping == NULL){
        DEBUG_PRINT("Failed to allocate sectionMapping\n");
        goto cleanup;
    }

    /* Handle the allocation and copying of the sections we're going to use
     * for right now I'm just VirtualAlloc'ing memory, this can be changed to
     * other methods, but leaving that up to the person implementing it. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t) + (sizeof(coff_sect_t) * counter));
        DEBUG_PRINT("Name: %s\n", coff_sect_ptr->Name);
        DEBUG_PRINT("VirtualSize: 0x%X\n", coff_sect_ptr->VirtualSize);
        DEBUG_PRINT("VirtualAddress: 0x%X\n", coff_sect_ptr->VirtualAddress);
        DEBUG_PRINT("SizeOfRawData: 0x%X\n", coff_sect_ptr->SizeOfRawData);
        DEBUG_PRINT("PointerToRelocations: 0x%X\n", coff_sect_ptr->PointerToRelocations);
        DEBUG_PRINT("PointerToRawData: 0x%X\n", coff_sect_ptr->PointerToRawData);
        DEBUG_PRINT("NumberOfRelocations: %d\n", coff_sect_ptr->NumberOfRelocations);
        relocationCount += coff_sect_ptr->NumberOfRelocations;
        /* NOTE: When changing the memory loading information of the loader,
         * you'll want to use this field and the defines from the Section
         * Flags table of Microsofts page, some defined in COFFLoader.h */
        DEBUG_PRINT("Characteristics: %x\n", coff_sect_ptr->Characteristics);
#ifdef _WIN32
        DEBUG_PRINT("Allocating 0x%x bytes\n", coff_sect_ptr->VirtualSize);
        /* NOTE: Might want to allocate as PAGE_READWRITE and VirtualProtect
         * before execution to either PAGE_READWRITE or PAGE_EXECUTE_READ
         * depending on the Section Characteristics. Parse them all again
         * before running and set the memory permissions. */
        sectionMapping[counter] = VirtualAlloc(NULL, coff_sect_ptr->SizeOfRawData, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
#ifdef DEBUG
        sectionSize[counter] = coff_sect_ptr->SizeOfRawData;
#endif
        if (sectionMapping[counter] == NULL) {
            DEBUG_PRINT("Failed to allocate memory\n");
        }
        DEBUG_PRINT("Allocated section %d at %p\n", counter, sectionMapping[counter]);
        if (coff_sect_ptr->PointerToRawData != 0){
            memcpy(sectionMapping[counter], coff_data + coff_sect_ptr->PointerToRawData, coff_sect_ptr->SizeOfRawData);
        }
        else{
            memset(sectionMapping[counter], 0, coff_sect_ptr->SizeOfRawData);
        }
#endif
    }
    DEBUG_PRINT("Total Relocations: %d\n", relocationCount);
    /* Allocate and setup the GOT for functions, same here as above. */
    /* Actually allocate enough for worst case every relocation, may not be needed, but hey better safe than sorry */
#ifdef _WIN32
#ifdef _WIN64
    functionMapping = (void **)VirtualAlloc(NULL, relocationCount*8, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
#else
    functionMapping = (void **)VirtualAlloc(NULL, relocationCount*8, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
#endif
    if (functionMapping == NULL){
        DEBUG_PRINT("Failed to allocate functionMapping\n");
        goto cleanup;
    }
#endif

    /* Start parsing the relocations, and *hopefully* handle them correctly. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        DEBUG_PRINT("Doing Relocations of section: %d\n", counter);
        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t) + (sizeof(coff_sect_t) * counter));
        coff_reloc_ptr = (coff_reloc_t*)(coff_data + coff_sect_ptr->PointerToRelocations);
        for (reloccount = 0; reloccount < coff_sect_ptr->NumberOfRelocations; reloccount++) {
            DEBUG_PRINT("\tVirtualAddress: 0x%X\n", coff_reloc_ptr->VirtualAddress);
            DEBUG_PRINT("\tSymbolTableIndex: 0x%X\n", coff_reloc_ptr->SymbolTableIndex);
            DEBUG_PRINT("\tType: 0x%X\n", coff_reloc_ptr->Type);

            /* Check if the symbol name is a long symbol name */
            if (coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[0] == 0) {
                /* Long symbol name from the string table */

                symbol_name = ((char*)(coff_sym_ptr + coff_header_ptr->NumberOfSymbols))
                    + coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[1];

            } else {
                /* Short symbol name */

                /* If the short symbol name is 8 bytes in length, it is not NULL
                 * terminated. Copy it to a temporary buffer to add the NULL terminator. */
                if (coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[7] != '\0') {
                    strncpy_s(
                        symbol_shortname_buffer,
                        sizeof(symbol_shortname_buffer),
                        &coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[0],
                        sizeof(coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name)
                    );

                    symbol_name = symbol_shortname_buffer;
                } else {
                    symbol_name = &coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[0];
                }
            }

            DEBUG_PRINT("\tSymNamePtr: %p\n", symbol_name);
            DEBUG_PRINT("\tSymName: %s\n", symbol_name);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);

            /* Check if the target symbol is a local symbol or an external undefined symbol
             * and resolve it */
            if (coff_symbol_is_defined(&coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])) {
                /* Locally defined symbol. Find the mapped address. */
                funcptrlocation = sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1];

                funcptrlocation = (void *)((char *)funcptrlocation + coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            } else if (coff_symbol_is_external(&coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])
                    && coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value == 0) {
                /* Imported symbol. Resolve it and map it in */
                funcptrlocation = process_symbol(symbol_name);
                if (funcptrlocation == NULL) {
                    DEBUG_PRINT("Failed resolving imported symbol '%s'\n", symbol_name);
                    retcode = 1;
                    goto cleanup;
                }

                /* Map the imported symbol address to the local import table */
                functionMapping[functionMappingCount] = funcptrlocation;

                /* Get the address of the imported symbol mapped in the local import 
                 * table for the relocation target */
                funcptrlocation = &functionMapping[functionMappingCount];

                /* Increment the number of mapped imported functions */
                functionMappingCount += 1;

            } else {
                /* Relocation to an undefined symbol */
                DEBUG_PRINT("Relocation %d in section index %d references undefined symbol %s\n", reloccount, counter, symbol_name);
                retcode = 1;
                goto cleanup;
            }

#ifdef _WIN32
#ifdef _WIN64
            /* Type == 1 relocation is the 64-bit VA of the relocation target */
            if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR64) {
                memcpy(&longoffsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(uint64_t));
                DEBUG_PRINT("\tReadin longOffsetValue : 0x%llX\n", longoffsetvalue);
                longoffsetvalue += (uint64_t)funcptrlocation;
                DEBUG_PRINT("\tModified longOffsetValue : 0x%llX Base Address: %p\n", longoffsetvalue, funcptrlocation);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &longoffsetvalue, sizeof(uint64_t));
            }
            /* This is Type == 3 relocation code */
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR32NB) {
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                DEBUG_PRINT("\t\tReferenced Section: 0x%X\n", sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue);
                DEBUG_PRINT("\t\tEnd of Relocation Bytes: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4);
                if (((char*)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue) - (char*)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }
                offsetvalue = ((char*)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue) - (char*)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                DEBUG_PRINT("\tSetting 0x%p to OffsetValue: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            /* This is Type == 4 relocation code, this is either a relocation to a global
             * or imported symbol */
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    goto cleanup;
                }

                offsetvalue += ((size_t)funcptrlocation - ((size_t)sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_1) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 1)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 1);
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_2) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 2)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 2));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_3) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 3)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 3));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_4) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 4)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 4));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_5) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 5)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 5));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else {
                DEBUG_PRINT("No code for relocation type: %d\n", coff_reloc_ptr->Type);
            }
#else
            /* This is Type == IMAGE_REL_I386_DIR32 relocation code */
            if (coff_reloc_ptr->Type == IMAGE_REL_I386_DIR32){
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                offsetvalue = (uint32_t)funcptrlocation + offsetvalue;
                DEBUG_PRINT("\tSetting 0x%p to: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_I386_REL32){
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                offsetvalue += (uint32_t)funcptrlocation - (uint32_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4);
                DEBUG_PRINT("\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
#endif //WIN64 statement close
#endif //WIN32 statement close

            DEBUG_PRINT("\tValueNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);
            coff_reloc_ptr += 1;
            DEBUG_PRINT("\n");
        }
        DEBUG_PRINT("\n");
    }

    /* Some debugging code to see what the sections look like in memory */
#if DEBUG
#ifdef _WIN32
    for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSections; tempcounter++) {
        DEBUG_PRINT("Section: %u\n", tempcounter);
        if (sectionMapping[tempcounter] != NULL) {
            DEBUG_PRINT("\t");
            for (counter = 0; counter < sectionSize[tempcounter]; counter++) {
                DEBUG_PRINT("%02X ", (uint8_t)(sectionMapping[tempcounter][counter]));
            }
            DEBUG_PRINT("\n");
        }
    }
#endif
#endif

    DEBUG_PRINT("Symbols:\n");
    for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSymbols; tempcounter++) {
        DEBUG_PRINT("\t%s: Section: %d, Value: 0x%X\n", coff_sym_ptr[tempcounter].first.Name, coff_sym_ptr[tempcounter].SectionNumber, coff_sym_ptr[tempcounter].Value);
        if (strcmp(coff_sym_ptr[tempcounter].first.Name, entryfuncname) == 0) {
            DEBUG_PRINT("\t\tFound entry!\n");
#ifdef _WIN32
            /* So for some reason VS 2017 doesn't like this, but char* casting works, so just going to do that */
#ifdef _MSC_VER
            foo = (void(__cdecl*)(char*, unsigned long))(sectionMapping[coff_sym_ptr[tempcounter].SectionNumber - 1] + coff_sym_ptr[tempcounter].Value);
#else
            foo = (void(*)(char *, unsigned long))(sectionMapping[coff_sym_ptr[tempcounter].SectionNumber - 1] + coff_sym_ptr[tempcounter].Value);
#endif
            //sectionMapping[coff_sym_ptr[tempcounter].SectionNumber-1][coff_sym_ptr[tempcounter].Value+7] = '\xcc';
            DEBUG_PRINT("Trying to run: %p\n", foo);
            foo((char*)argumentdata, argumentSize);
#endif
        }
    }
    DEBUG_PRINT("Back\n");

    /* Cleanup the allocated memory */
#ifdef _WIN32
    cleanup :
            if (sectionMapping){
                for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSections; tempcounter++) {
                    if (sectionMapping[tempcounter]) {
                        VirtualFree(sectionMapping[tempcounter], 0, MEM_RELEASE);
                    }
                }
                free(sectionMapping);
                sectionMapping = NULL;
            }
#ifdef DEBUG
            if (sectionSize){
                free(sectionSize);
                sectionSize = NULL;
            }
#endif
            if (functionMapping){
                VirtualFree(functionMapping, 0, MEM_RELEASE);
            }
#endif
            if (entryfuncname && entryfuncname != functionname){
                free(entryfuncname);
            }

            DEBUG_PRINT("Returning\n");
            return retcode;
}

char* COFFLoader_GetOutputData(int *outsize) {
    if (outsize == NULL) {
        return NULL;
    }

    char* outdata = beacon_compatibility_output;
    *outsize = beacon_compatibility_size;
    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;
    return outdata;
}
