/*
 * COFF Loader Project
 * -------------------
 * This is a re-implementation of a COFF loader, with a BOF compatibility layer
 * it's meant to provide functional example of loading a COFF file in memory
 * and maybe be useful.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include "beacon_compatibility.h"
#endif

#include <COFFLoader/COFFLoader.h>

/* These seem to be the same sizes across architectures, relocations are different though. Defined both sets of types. */

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

#pragma pack(push,1)

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
/* AMD64 Specific types */
#define IMAGE_REL_AMD64_ABSOLUTE    0x0000
#define IMAGE_REL_AMD64_ADDR64      0x0001
#define IMAGE_REL_AMD64_ADDR32      0x0002
#define IMAGE_REL_AMD64_ADDR32NB    0x0003
/* Most common from the looks of it, just 32-bit relative address from the byte following the relocation */
#define IMAGE_REL_AMD64_REL32       0x0004
/* Second most common, 32-bit address without an image base. Not sure what that means... */
#define IMAGE_REL_AMD64_REL32_1     0x0005
#define IMAGE_REL_AMD64_REL32_2     0x0006
#define IMAGE_REL_AMD64_REL32_3     0x0007
#define IMAGE_REL_AMD64_REL32_4     0x0008
#define IMAGE_REL_AMD64_REL32_5     0x0009
#define IMAGE_REL_AMD64_SECTION     0x000A
#define IMAGE_REL_AMD64_SECREL      0x000B
#define IMAGE_REL_AMD64_SECREL7     0x000C
#define IMAGE_REL_AMD64_TOKEN       0x000D
#define IMAGE_REL_AMD64_SREL32      0x000E
#define IMAGE_REL_AMD64_PAIR        0x000F
#define IMAGE_REL_AMD64_SSPAN32     0x0010

/*i386 Relocation types */

#define IMAGE_REL_I386_ABSOLUTE     0x0000
#define IMAGE_REL_I386_DIR16        0x0001
#define IMAGE_REL_I386_REL16        0x0002
#define IMAGE_REL_I386_DIR32        0x0006
#define IMAGE_REL_I386_DIR32NB      0x0007
#define IMAGE_REL_I386_SEG12        0x0009
#define IMAGE_REL_I386_SECTION      0x000A
#define IMAGE_REL_I386_SECREL       0x000B
#define IMAGE_REL_I386_TOKEN        0x000C
#define IMAGE_REL_I386_SECREL7      0x000D
#define IMAGE_REL_I386_REL32        0x0014

/* Section Characteristic Flags */

#define IMAGE_SCN_MEM_WRITE 0x80000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_ALIGN_16BYTES 0x00500000
#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
#define IMAGE_SCN_MEM_SHARED 0x10000000
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000


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

#define COFFLOADER_RETURN_VAL_IF(expr, val, fmt, ...) if ((expr)) { DEBUG_PRINT(fmt, ##__VA_ARGS__); return val; }


static BOOL starts_with(const char* string, const char* substring) {
    return strncmp(string, substring, strlen(substring)) == 0;
}

/* Helper function to process a symbol string, determine what function and
 * library its from, and return the right function pointer. Will need to
 * implement in the loading of the beacon internal functions, or any other
 * internal functions you want to have available. */
void* process_symbol(char* symbolstring) {
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
    uint32_t symptr = 0;

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
    char* functionMapping = NULL;
    int functionMappingCount = 0;
    int relocationCount = 0;
#endif

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
    functionMapping = VirtualAlloc(NULL, relocationCount*8, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
#else
    functionMapping = VirtualAlloc(NULL, relocationCount*8, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
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
            if (coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[0] != 0) {
                symptr = coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[1];
                DEBUG_PRINT("\tSymPtr: 0x%X\n", symptr);
                DEBUG_PRINT("\tSymName: %s\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name);
                DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);

                /* This is the code for relative offsets in other sections of the COFF file. */
#ifdef _WIN32
#ifdef _WIN64
            /* Type == 1 relocation is the 64-bit VA of the relocation target */
                if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR64) {
                    memcpy(&longoffsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(uint64_t));
                    DEBUG_PRINT("\tReadin longOffsetValue : 0x%llX\n", longoffsetvalue);
                    longoffsetvalue = (uint64_t)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + (uint64_t)longoffsetvalue);
                    longoffsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    DEBUG_PRINT("\tModified longOffsetValue : 0x%llX Base Address: %p\n", longoffsetvalue, sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1]);
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
                /* This is Type == 4 relocation code, needed to make global variables to work correctly */
                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32) {
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);
                    if ((sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }
                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_1) {
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);
                    if ((sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    offsetvalue += 1;
                    DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }

                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_2) {
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);
                    if ((sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    offsetvalue += 2;
                    DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }

                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_3) {
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);
                    if ((sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    offsetvalue += 3;
                    DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }

                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_4) {
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);
                    if ((sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    offsetvalue += 4;
                    DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }
                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_5) {
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);
                    if ((sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    offsetvalue += 5;
                    DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }

                else {
                    DEBUG_PRINT("No code for relocation type: %d\n", coff_reloc_ptr->Type);
                }
#else
             /* This is Type == IMAGE_REL_I386_DIR32 relocation code */
                if (coff_reloc_ptr->Type == IMAGE_REL_I386_DIR32){
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                    offsetvalue = (uint32_t)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1]) + offsetvalue;
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    DEBUG_PRINT("\tSetting 0x%p to: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }
                else if (coff_reloc_ptr->Type == IMAGE_REL_I386_REL32){
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    DEBUG_PRINT("\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                    
                }
#endif //WIN64 statement close
#endif //WIN32 statement close
            }
            else {
                symptr = coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[1];
                DEBUG_PRINT("\tSymPtr: 0x%X\n", symptr);
                DEBUG_PRINT("\tSymVal: %s\n", ((char*)(coff_sym_ptr + coff_header_ptr->NumberOfSymbols)) + symptr);
                DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);

                /* This is the code to handle functions themselves, so using a makeshift Global Offset Table for it */
#ifdef _WIN32
                funcptrlocation = process_symbol(((char*)(coff_sym_ptr + coff_header_ptr->NumberOfSymbols)) + symptr);
                if (funcptrlocation == NULL && coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber == 0) {
                    DEBUG_PRINT("Failed to resolve symbol\n");
                    retcode = 1;
                    goto cleanup;
                }
#ifdef _WIN64
                if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR64) {
                    memcpy(&longoffsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(uint64_t));
                    DEBUG_PRINT("\tReadin longOffsetValue : 0x%llX\n", longoffsetvalue);
                    longoffsetvalue = (uint64_t)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + (uint64_t)longoffsetvalue);
                    longoffsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    DEBUG_PRINT("\tModified longOffsetValue : 0x%llX Base Address: %p\n", longoffsetvalue, sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1]);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &longoffsetvalue, sizeof(uint64_t));
                }

                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32 && funcptrlocation != NULL) {
                    /* This is Type == 4 relocation code */
                    DEBUG_PRINT("Doing function relocation\n");
                    if (((functionMapping + (functionMappingCount * 8)) - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    memcpy(functionMapping + (functionMappingCount * 8), &funcptrlocation, sizeof(uint64_t));
                    offsetvalue = (int32_t)((functionMapping + (functionMappingCount * 8)) - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                    functionMappingCount++;
                }
                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32) {
                    /* This shouldn't be needed here, but incase there's a defined symbol
                     * that somehow doesn't have a function, try to resolve it here.*/
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    if ((sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    DEBUG_PRINT("\t\tReferenced Section: 0x%X\n", sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue);
                    DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);
                    DEBUG_PRINT("\t\tVirtualAddressOffset: 0x%X\n", (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }
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
                else {
                    DEBUG_PRINT("No code for relocation type: %d\n", coff_reloc_ptr->Type);
                }
#else
                if (coff_reloc_ptr->Type == IMAGE_REL_I386_DIR32 && funcptrlocation != NULL){
                    /* This is Type == IMAGE_REL_I386_DIR32 relocation code */
                    memcpy(functionMapping + (functionMappingCount * 4), &funcptrlocation, sizeof(uint32_t));
                    offsetvalue = (int32_t)(functionMapping + (functionMappingCount * 4));
                    DEBUG_PRINT("\tSetting 0x%p to virtual address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                    functionMappingCount++;
                }
                else if (coff_reloc_ptr->Type == IMAGE_REL_I386_DIR32) {
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                    offsetvalue = (uint32_t)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1]) + offsetvalue;
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    DEBUG_PRINT("\tSetting 0x%p to virtual address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }
                else if (coff_reloc_ptr->Type == IMAGE_REL_I386_REL32){
                    memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                    DEBUG_PRINT("\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                    memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                    
                }
                else {
                    DEBUG_PRINT("No code for relocation type: %d\n", coff_reloc_ptr->Type);
                }
#endif
#endif
            }
            DEBUG_PRINT("\tValueNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);
            coff_reloc_ptr = (coff_reloc_t*)(((char*)coff_reloc_ptr) + sizeof(coff_reloc_t));
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
