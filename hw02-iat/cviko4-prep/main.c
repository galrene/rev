#include <stdio.h>
#include <windows.h>
#include <winuser.h>

// useful windows commands
// =======================
/**
 * > dumpbin /imports main.exe
 *     api-ms-win-crt-heap-l1-1-0.dll
             140006140 Import Address Table
             140009188 Import Name Table
                     0 time date stamp
                     0 Index of first forwarder reference

                          19 malloc
                          16 _set_new_mode
                          17 calloc
                          18 free
 */
//
// compile with address sanitizer
// cl /fsanitize=address /Zi /Od /MD main.c
// 
// compile and run in powershell that doesn't support && operator :)
// cl /MD main.c; if ($LASTEXITCODE -eq 0) { .\main.exe }

// function pointer declaration
// ============================
// RETURN_TYPE (*FUNCTION_NAME)(ARG1_TYPE, ARG2_TYPE, ...);

void * (*g_OrigMalloc)(size_t);
// calloc
// realloc
void (*g_OrigFree)(void *);

/**
 * Najde v IAT pozici funkcí malloc, calloc, realloc
 * a free a změní jejich adresu na adresy substitučních funkcí
 */
void MallocDebug_Init (void) {
}
/**
 * Vrátí IAT do původního stavu a vypíše případné zbytky tabulky,
 * které budou považovány za memory leaky :)
 */
void MallocDebug_Done (void) {}


#define ALLOCATIONS_MAX 50
size_t g_AllocatedMemory[ALLOCATIONS_MAX]     = {0};
size_t g_AllocatedMemorySize[ALLOCATIONS_MAX] = {0};
size_t g_AllocCnt = 0;

/**
 * loguju:
 * 1. pamat sa alokovala
 * 2. velkost alokovanej pamate
 */
void * MallocDebug_malloc (size_t size) {
    printf("User wants to allocate %zu bytes\n", size);
    
    void * ptr = g_Origmalloc(size);
    g_AllocatedMemory[g_AllocCnt++] = ptr;
    g_AllocatedMemorySize[g_AllocCnt++] = size;
    return ptr;
}
void MallocDebug_calloc (void) {}
void MallocDebug_realloc (void) {}

/**
 * Budou záznam [alokace] rušit
 * stěžovat si, pokud by měly zrušit neznámou,
 * nebo uz dříve zrušenou alokaci
 */
void MallocDebug_free (void * ptr) {
    printf("User wants to free %p\n", ptr);
    
    for (size_t i = 0; i < g_AllocCnt; ++i) {
        if (g_AllocatedMemory[i] == ptr) {
            g_AllocatedMemory[i] = 0;
            --g_AllocCnt;
            g_OriginalFree(ptr);
            return;
        }
    }

    puts("Requested memory isn't allocated - already freed or never allocated.");
    return;
}

/*
 * Import Directory    : metadata that describes what to import
 * Import Address Table: table with resolved addresses
 */
#define hBEGIN ((BYTE*)pDosHeader)

static BOOL UnlockFirstThunk(PIMAGE_DOS_HEADER pDosHeader, PIMAGE_IMPORT_DESCRIPTOR pImp)
{   
    PIMAGE_THUNK_DATA t = (PIMAGE_THUNK_DATA)(hBEGIN + pImp->FirstThunk);

    SIZE_T count = 0;
    while (t[count].u1.Function != 0)
        count++;

    SIZE_T pBytes  = count * sizeof(IMAGE_THUNK_DATA);
    DWORD pOldProt = 0;
    return VirtualProtect(t, pBytes, PAGE_READWRITE, &pOldProt);
}

void printFirstThunks (PIMAGE_DOS_HEADER pDosHeader, PIMAGE_IMPORT_DESCRIPTOR pImportDesc)
{
    // PIMAGE_THUNK_DATA arr is 0-terminated
    for (PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA) (hBEGIN + pImportDesc->FirstThunk);
        pFirstThunk->u1.AddressOfData != 0; ++pFirstThunk)
        {
            // check if address of data is ordinal
            // a teda ci pFirstThunk->u1.Function je typu PIMAGE_THUNK_DATA 
            void * pImportByName;
            if ( isOrdinalThunk(pFirstThunk) ) {
                pImportByName = (PIMAGE_THUNK_DATA) (hBEGIN + pFirstThunk->u1.Function);
                // pImportByName is now PIMAGE_THUNK_DATA
                printf("Found an ordinal, won't have a name!\n");
                continue;
            }
            else {
                pImportByName = (PIMAGE_IMPORT_BY_NAME) (hBEGIN + pFirstThunk->u1.Function);
                // pImportByName is now PIMAGE_IMPORT_BY_NAME
            }
            if ((ULONG_PTR)&malloc == pFirstThunk->u1.Function) {

                printf("\t pFirstThunk->u1.Function:\t\t%p\n", (void *) pFirstThunk->u1.Function);
                printf("\t &malloc:\t\t\t\t%p\n", (void *)&malloc);
                printf("\t &MallocDebug_malloc:\t\t\t%p\n", (void *)&MallocDebug_malloc);
                
                puts("Found malloc.");

                if ( UnlockFirstThunk(pDosHeader, pImportDesc) == 0) {
                    DWORD r = GetLastError();
                    printf("VirtualProtect failed.\n Error: %d\n", r);
                    return;
                }
                puts("Unlocked it's IAT for writing.\n");
                
                pFirstThunk->u1.Function = (ULONGLONG) &MallocDebug_malloc;
                
                puts("Replaced malloc with MallocDebug_malloc.\n");
                
                puts("Calling malloc, should run MallocDebug:");
                
                int * ptr = malloc(5);
            }
            
        }
}

// When MSB of AddressOfData is 1, it's an ordinal and
// pFirstThunk->u1.AddressOfData is of type PIMAGE_THUNK_DATA.

BOOL isOrdinalThunk(PIMAGE_THUNK_DATA pThunk)
{
    return IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal) ? TRUE : FALSE;
}


int printOGFirstThunks (PIMAGE_DOS_HEADER pDosHeader, PIMAGE_IMPORT_DESCRIPTOR pImportDesc)
{
    char * libName = ( hBEGIN + pImportDesc->Name );
    // if (strncmp(libName, "api-ms-win-crt-heap-l1-1-0.dll", 30) != 0)
        // return;
    // printf("OriginalFirstThunks: \n");
    printf("Library name: %s\n", libName);
    // timedatestamp will be non-zero if imports are bound
    printf("Import bound? ");
    printf(pImportDesc->TimeDateStamp != 0UL ? "Yes\n" : "No\n");

    int cnt = 0;
    printf("Found linked functions:\n");
    // PIMAGE_THUNK_DATA arr is 0-terminated
    for (PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA) (hBEGIN + pImportDesc->OriginalFirstThunk);
        pOriginalFirstThunk->u1.AddressOfData != 0; ++pOriginalFirstThunk)
        {
            // check if address of data is ordinal
            // a teda ci pFirstThunk->u1.AddressOfData je typu PIMAGE_THUNK_DATA 
            void * pImportByName;
            if ( isOrdinalThunk(pOriginalFirstThunk) ) {
                pImportByName = (PIMAGE_THUNK_DATA) (hBEGIN + pOriginalFirstThunk->u1.AddressOfData);
                // pImportByName is now PIMAGE_THUNK_DATA
                printf("Found an ordinal, won't have a name!\n");
                continue;
            }
            else {
                pImportByName = (PIMAGE_IMPORT_BY_NAME) (hBEGIN + pOriginalFirstThunk->u1.AddressOfData);
                // pImportByName is now PIMAGE_IMPORT_BY_NAME
            }
    
            char buf[64] = {0};
            if ( strcpy_s(buf, 64, ((PIMAGE_IMPORT_BY_NAME) pImportByName)->Name) == 0 ) {
                printf("\t- %s\n", buf);
                if (strncmp("malloc", buf, 6) == 0) {
                    // printf("\t# Found malloc!\n");
                    printf("\t# malloc's hint: %d\n", ((PIMAGE_IMPORT_BY_NAME) pImportByName)->Hint);
                    return 1;
                    // pImportByName = (PIMAGE_IMPORT_BY_NAME) (hBEGIN + pFirstThunk->u1.AddressOfData);
                    // printFirstThunks(pDosHeader, pImportDesc, pImportByName);
                    // IAT of heap dll: program_offset + 303C
                }
                ++cnt;
            }
            else {
                printf("Copying to buffer failed.\n");
            }
        }
    printf("Found %d linked functions in %s.\n", cnt, libName);
    return 0;
}

int main (void) {
    HMODULE hPEFile = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS) ( hBEGIN + pDosHeader->e_lfanew );

    // 1 import descriptor per linked DLL
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)
    (hBEGIN + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    // end does not point at a descriptor, it's a stopper filled with 0's
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

    for (; (pImportDescriptor != pImportDescriptorEnd) && (pImportDescriptor->Characteristics != 0); ++pImportDescriptor) {
        ("======================================\n");
        if ( printOGFirstThunks(pDosHeader, pImportDescriptor) == 1) {
            printf("Found malloc's lib, reading import addresses:\n");
            printFirstThunks(pDosHeader, pImportDescriptor);
            break;
        }
        printf("======================================\n");
    }
    
    free(ptr);
    
    return 0;
}