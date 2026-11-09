#include <stdio.h>
#include <windows.h>
#include <winuser.h>

#define ALLOCATIONS_MAX 10000

size_t g_AllocatedMemSize[ALLOCATIONS_MAX] = {0};

/**
 * Najde v IAT pozici funkcí malloc, calloc, realloc
 * a free a změní jejich adresu na adresy substitučních funkcí
 */
void MallocDebug_Init (void) {
// 1. Chceme povolit zapis do IAT
    // BOOL WINAPI VirtualProtect (
    //   (LPVOID) lpAddress,   // adresa bloku, jehož stav ochrany chceme měnit
    //   (size_t) dwSize,      // velikost bloku
    //   PAGE_READWRITE,       // příznaky ochrany bloku
    //   (PDWORD)&dwOldProtect // stará hodnota příznaků
    // );

}
/**
 * Vrátí IAT do původního stavu a vypíše případné zbytky tabulky,
 * které budou považovány za memory leaky :)
 */
void MallocDebug_Done (void) {}

/**
 * loguju:
 * 1. pamat sa alokovala
 * 2. velkost alokovanej pamate
 */
void MallocDebug_malloc (void) {
}
void MallocDebug_calloc (void) {}
void MallocDebug_realloc (void) {}
/**
 * Uvolňující substituční funkce budou tento záznam opět rušit
 * (a stěžovat si, pokud by měly zrušit neznámou nebo uz dříve
 * zrušenou alokaci).
 */
void MallocDebug_free (void) {
}

/*
 * Import Directory    : metadata that describes what to import
 * Import Address Table: table with resolved addresses
 */
#define hBEGIN ((BYTE*)pDosHeader)

void printLinkedFuns (PIMAGE_DOS_HEADER pDosHeader, PIMAGE_IMPORT_DESCRIPTOR pImportDesc)
{
    char * libName = ( hBEGIN + pImportDesc->Name );
    printf("Library name: %s\n", libName);

    int cnt = 0;
    printf("Found linked functions:\n");
    for (PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA) (hBEGIN + pImportDesc->OriginalFirstThunk);
        pOriginalFirstThunk->u1.AddressOfData != 0; ++pOriginalFirstThunk)
        {
            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME) (hBEGIN + pOriginalFirstThunk->u1.AddressOfData);
            char buf[64] = {0};
            if ( strcpy_s(buf, 64, pImportByName->Name) == 0 ) {
                printf("\t- %s\n", buf);
                if (strncmp("malloc", buf, 6) == 0) {
                    printf("Found malloc!\n");
                    // maybe need to change type here
                    printf("malloc import address (FirstThunk): %p\n", pImportDesc->FirstThunk);
                    // prints 0000303C
                    // IAT of heap.dll: program_offset + 303C
                }
                ++cnt;
            }
            else {
                printf("Copying to buffer failed.\n");
            }
        }
    printf("Found %d linked functions in %s.\n", cnt, libName);
}
/**
      api-ms-win-crt-heap-l1-1-0.dll
                40303C Import Address Table
                4035E4 Import Name Table
                     0 time date stamp
                     0 Index of first forwarder reference

                   16 _set_new_mode
                   18 free
                   19 malloc 
 */
int main (void) {
    HMODULE hPEFile = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS) ( hBEGIN + pDosHeader->e_lfanew );

    // IAT
    PIMAGE_IMPORT_DESCRIPTOR pImportAddressTable = (PIMAGE_IMPORT_DESCRIPTOR)
    (hBEGIN + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);

    // 1 import descriptor per linked DLL
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)
    (hBEGIN + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    // end does not point at a descriptor, it's a stopper
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptorEnd = (PIMAGE_IMPORT_DESCRIPTOR)
    (((BYTE*)pImportDescriptor) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

#ifdef TEST1
    // dummy functions for testing
    HANDLE hFile = CreateFile("test.txt",             // name of the write
                              GENERIC_WRITE,          // open for writing
                              0,                      // do not share
                              NULL,                   // default security
                              CREATE_NEW,             // create new file only
                              FILE_ATTRIBUTE_NORMAL,  // normal file
                              NULL);                  // no attr. template
    int result = MessageBoxA(
        NULL,                        // No owner window
        "Hello, this is MessageBoxA!", // Message text
        "API Example",               // Title bar text
        MB_OK | MB_ICONINFORMATION   // OK button + Info icon
    );
#endif
    void * ptr = malloc(9);
    for (; pImportDescriptor != pImportDescriptorEnd; ++pImportDescriptor) {
        ("======================================\n");
        printLinkedFuns(pDosHeader, pImportDescriptor);
        // printLinkedFuns(pDosHeader, pImportDescriptorEnd);
        printf("======================================\n");
    }
    free(ptr);
    return 0;
}
