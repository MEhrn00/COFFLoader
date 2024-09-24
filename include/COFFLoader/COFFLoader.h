#ifndef COFFLOADER_COFFLOADER_H
#define COFFLOADER_COFFLOADER_H

#include <stdint.h>

int RunCOFF(char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize);

#endif // COFFLOADER_COFFLOADER_H
