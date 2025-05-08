#ifndef COFFLOADER_H_
#define COFFLOADER_H_

#include <stdint.h>

int COFFLoader_RunCOFF(char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize);
char *COFFLoader_GetOutputData(int *outsize);

#endif
