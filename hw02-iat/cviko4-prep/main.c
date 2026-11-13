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

#define hBEGIN ((BYTE*)pDosHeader)

// convert relative virtual address to virtual address (absolute address in memory)
static void * VA(DWORD rva)
{
    BYTE *base = (BYTE *)GetModuleHandle(NULL);
    return base + rva;
}

PIMAGE_IMPORT_DESCRIPTOR getFirstImpDesc (void) {
    HMODULE hPEFile = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS) ( VA(pDosHeader->e_lfanew) );
    
    // 1 import descriptor per imported DLL
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)
    (hBEGIN + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    return pImportDesc;
}

PIMAGE_IMPORT_DESCRIPTOR findImpDescOfFunc (char * funcName) {
    for ( PIMAGE_IMPORT_DESCRIPTOR pImportDesc = getFirstImpDesc();
          pImportDesc->Characteristics != 0; ++pImportDesc) 
    {
        for ( PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA) (VA(pImportDesc->OriginalFirstThunk));
              pOriginalFirstThunk->u1.AddressOfData != 0; ++pOriginalFirstThunk)
        {
            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME) 
            (VA(pOriginalFirstThunk->u1.AddressOfData));
    
            if (strncmp("malloc", pImportByName->Name, 6) == 0) {
                return pImportDesc;
            }
        }
    }
    return NULL;
}

static BOOL UnlockFirstThunk(PIMAGE_IMPORT_DESCRIPTOR pImp)
{   
    PIMAGE_THUNK_DATA t = (PIMAGE_THUNK_DATA)(VA(pImp->FirstThunk));

    SIZE_T count = 0;
    while (t[count].u1.Function != 0)
        count++;

    SIZE_T pBytes  = count * sizeof(IMAGE_THUNK_DATA);
    DWORD pOldProt = 0;
    return VirtualProtect(t, pBytes, PAGE_READWRITE, &pOldProt);
}

BOOL replaceFunc (char * funcName, ULONGLONG funcAddr, ULONGLONG pNewFunc) { 
    // find import descriptor of funcName's .dll
    PIMAGE_IMPORT_DESCRIPTOR funcImpDesc = findImpDescOfFunc(funcName);
    if ( funcImpDesc == NULL ) {
        printf("No Import Descriptor containing function %s found\n", funcName);
        return FALSE;
    }

    // find the func's address in FirstThunk, replace with pNewFunc
    //    - alebo ju viem retrievnut aj podla poradia/inak dajak?
    for ( PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA) (VA(funcImpDesc->FirstThunk));
          pFirstThunk->u1.AddressOfData != 0; ++pFirstThunk)
    {
        if ( funcAddr == pFirstThunk->u1.Function ) {
            if ( UnlockFirstThunk(funcImpDesc) == 0) {
                DWORD r = GetLastError();
                printf("Unlocking FirstThunk memory for writing failed.\n Error: %d\n", r);
                return FALSE;
            }
            pFirstThunk->u1.Function = pNewFunc;
            return TRUE;
        }
    }
    printf("Given function's address not found in FirstThunk, something's wroong.");
    return FALSE;
}


// function pointer declaration
// ============================
// RETURN_TYPE (*FUNCTION_NAME)(ARG1_TYPE, ARG2_TYPE, ...);

void * (*g_OrigMalloc)(size_t)          = NULL; // void * malloc(size)
void * (*g_OrigCalloc)(size_t, size_t)  = NULL; // void * calloc(count, size)
void * (*g_OrigRealloc)(void *, size_t) = NULL; // void * calloc(ptr, newSize)
void   (*g_OrigFree)(void *)            = NULL; // void   free (ptr)

void * MallocDebug_malloc (size_t size);
void MallocDebug_free (void * ptr);
/**
 * Najde v IAT pozici funkcí malloc, calloc, realloc
 * a free a změní jejich adresu na adresy substitučních funkcí
 */
BOOL MallocDebug_Init (void) {
    if (g_OrigMalloc != NULL) { // or other func is not NULL
        puts("Init already called - not doing anything.");
        return FALSE;
    }
    // backup original function addresses
    g_OrigMalloc  = &malloc;
    // g_OrigCalloc  = &calloc;
    // g_OrigRealloc = &realloc;
    g_OrigFree    = &free;

    if ( ! replaceFunc("malloc", &g_OrigMalloc, &MallocDebug_malloc)) {
        puts("Replacing malloc failed.");
        return FALSE;
    }
    // if ( ! replaceFunc("calloc", &g_OrigCalloc, &MallocDebug_calloc) ) {
    //     puts("Replacing calloc failed.");
    //     return FALSE;
    // }
    // if ( ! replaceFunc("realloc", &g_OrigRealloc , &MallocDebug_realloc) ) {
    //     puts("Replacing realloc failed.");
    //     return FALSE;
    // }
    if ( ! replaceFunc("free", &g_OrigFree, &MallocDebug_free) ) {
        puts("Replacing free failed.");
        return FALSE;
    }
    return TRUE;
}

#define ALLOCATIONS_MAX 50
size_t g_AllocatedMemory[ALLOCATIONS_MAX]     = {0};
size_t g_AllocatedMemorySize[ALLOCATIONS_MAX] = {0};
size_t g_AllocCnt = 0;

/**
 * Vrátí IAT do původního stavu a vypíše případné zbytky tabulky,
 * které budou považovány za memory leaky :)
 */
void MallocDebug_Done (void) {
    // restore original IAT state
    if (g_OrigMalloc != NULL) {
        // replaceFunc("malloc", g_OrigMalloc);
        // replaceFunc("calloc", g_OrigCalloc);
        // replaceFunc("realloc", g_OrigRealloc);
        // replaceFunc("free", g_OrigFree);
    }

    // print memory leaks
    if (g_AllocCnt != 0) {
        puts("Memory leaks detected.");
        for (size_t i = 0; i < ALLOCATIONS_MAX; ++i) {
            if (g_AllocatedMemorySize[i] != 0) {
                printf("Leaked %d bytes @%p\n", g_AllocatedMemorySize[i], g_AllocatedMemory[i]);
            }
        }
    }
    puts("Original function addresses restored.");
}

/**
 * loguju:
 * 1. pamat sa alokovala
 * 2. velkost alokovanej pamate
 */
void * MallocDebug_malloc (size_t size) {
    if (g_AllocCnt >= ALLOCATIONS_MAX) {
        puts("Maximum allocations reached, not allocating anything.");
        return;
    }    
    
    void * ptr = g_OrigMalloc(size);
    g_AllocatedMemory[g_AllocCnt++] = ptr;
    g_AllocatedMemorySize[g_AllocCnt++] = size;

    printf("Allocated %zu bytes @%p\n", size, ptr);
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
    for (size_t i = 0; i < ALLOCATIONS_MAX; ++i) {
        if (g_AllocatedMemory[i] == ptr) {
            g_AllocatedMemory[i] = 0;
            --g_AllocCnt;
            g_OrigFree(ptr);
            printf("Freed memory @%p\n", ptr);
            return;
        }
    }

    puts("Requested memory isn't allocated - already freed or never allocated.");
    return;
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

                if ( UnlockFirstThunk(pImportDesc) == 0) {
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

void printStuff (void) {
    HMODULE hPEFile = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS) ( hBEGIN + pDosHeader->e_lfanew );

    // 1 import descriptor per imported DLL
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
}

int main (void) {
    if ( ! MallocDebug_Init() ) {
        return 1;
    }
    return 0;
}