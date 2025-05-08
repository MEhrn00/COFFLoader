#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <COFFLoader/COFFLoader.h>


static unsigned char* unhexlify(unsigned char* value, int *outlen) {
    unsigned char* retval = NULL;
    char byteval[3] = { 0 };
    unsigned int counter = 0;
    int counter2 = 0;
    char character = 0;
    if (value == NULL) {
        return NULL;
    }
    printf("Unhexlify Strlen: %lu\n", (long unsigned int)strlen((char*)value));
    if (strlen((char*)value) % 2 != 0) {
        printf("Either value is NULL, or the hexlified string isn't valid\n");
        goto errcase;
    }

    retval = calloc(strlen((char*)value) + 1, 1);
    if (retval == NULL) {
        goto errcase;
    }

    counter2 = 0;
    for (counter = 0; counter < strlen((char*)value); counter += 2) {
        memcpy(byteval, value + counter, 2);
        character = (char)strtol(byteval, NULL, 16);
        memcpy(retval + counter2, &character, 1);
        counter2++;
    }
    *outlen = counter2;

errcase:
    return retval;
}



/* Helper to just get the contents of a file, used for testing. Real
 * implementations of this in an agent would use the tasking from the
 * C2 server for this */
static unsigned char* getContents(char* filepath, uint32_t* outsize) {
    FILE *fin = NULL;
    uint32_t fsize = 0;
    size_t readsize = 0;
    unsigned char* buffer = NULL;
    unsigned char* tempbuffer = NULL;

    fin = fopen(filepath, "rb");
    if (fin == NULL) {
        return NULL;
    }
    fseek(fin, 0, SEEK_END);
    fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    tempbuffer = calloc(fsize, 1);
    if (tempbuffer == NULL) {
        fclose(fin);
        return NULL;
    }
    memset(tempbuffer, 0, fsize);
    readsize = fread(tempbuffer, 1, fsize, fin);

    fclose(fin);
    buffer = calloc(readsize, 1);
    if (buffer == NULL) {
        free(tempbuffer);
        return NULL;
    }
    memset(buffer, 0, readsize);
    memcpy(buffer, tempbuffer, readsize - 1);
    free(tempbuffer);
    *outsize = fsize;
    return buffer;
}


int main(int argc, char* argv[]) {
    char* coff_data = NULL;
    unsigned char* arguments = NULL;
    int argumentSize = 0;
#ifdef _WIN32
    char* outdata = NULL;
    int outdataSize = 0;
#endif
    uint32_t filesize = 0;
    int checkcode = 0;
    if (argc < 3) {
        printf("ERROR: %s go /path/to/object/file.o (arguments)\n", argv[0]);
        return 1;
    }

    coff_data = (char*)getContents(argv[2], &filesize);
    if (coff_data == NULL) {
        return 1;
    }
    printf("Got contents of COFF file\n");
    arguments = unhexlify((unsigned char*)argv[3], &argumentSize);
    printf("Running/Parsing the COFF file\n");
    checkcode = COFFLoader_RunCOFF(argv[1], (unsigned char*)coff_data, filesize, arguments, argumentSize);
    if (checkcode == 0) {
#ifdef _WIN32
        printf("Ran/parsed the coff\n");
        outdata = COFFLoader_GetOutputData(&outdataSize);
        if (outdata != NULL) {

            printf("Outdata Below:\n\n%s\n", outdata);
        }
#endif
    }
    else {
        printf("Failed to run/parse the COFF file\n");
    }
    if (coff_data) {
        free(coff_data);
    }
    return 0;
}
