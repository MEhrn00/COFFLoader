#ifndef COFFLOADER_H
#define COFFLOADER_H

#include <stdint.h>

#include <COFFLoader/export.h>

typedef int (*COFFLoader_goCallback)(char *, int);

COFFLOADER_EXPORT int __cdecl COFFLoader_LoadAndRun(char *argsBuffer, uint32_t bufferSize,
                                                    COFFLoader_goCallback callback);

COFFLOADER_EXPORT int COFFLoader_RunCOFF(char *functionname, unsigned char *coff_data,
                                         uint32_t filesize, unsigned char *argumentdata,
                                         int argumentSize, COFFLoader_goCallback data);

COFFLOADER_EXPORT char *COFFLoader_GetOutputData(int *outsize);

#endif // COFFLOADER_H
