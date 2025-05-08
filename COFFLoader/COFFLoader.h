#ifndef COFFLOADER_COFFLOADER_H
#define COFFLOADER_COFFLOADER_H

#include <COFFLoader/export.h>

#include <stdint.h>

COFFLOADER_API int COFFLoader_RunCOFF(char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize);
COFFLOADER_API char *COFFLoader_GetOutputData(int *outsize);

#endif
