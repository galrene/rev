#include <stdio.h>
#include <windows.h>
#include <winuser.h>
#include <assert.h>

// useful windows commands
// =======================
//
// compile with address sanitizer (+ /MD)
// cl /fsanitize=address /Zi /Od /MD main.c
//
// compile and run in powershell version that doesn't support && operator :))
// cl /MD main.c; if ($LASTEXITCODE -eq 0) { .\main.exe }

/**
PRISTUP
=======
Najdem img import descriptor (.dll) cez meno (v OGFirstThunkoch)
potom v nom hladam podla adresy moju funkciu vo FirstThunkoch, nahradim.

VYLEPSENIA
==========
1. Ries ordinal imports
2. Zamykaj IAT po prepisani

*/


// convert relative virtual address to virtual address (absolute address in memory)
static void *VA(DWORD rva)
{
    BYTE *base = (BYTE *)GetModuleHandle(NULL);
    return base + rva;
}

PIMAGE_IMPORT_DESCRIPTOR getFirstImpDesc(void)
{
    HMODULE hPEFile = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(VA(pDosHeader->e_lfanew));

    // 1 import descriptor per imported DLL
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE *)pDosHeader) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    return pImportDesc;
}

static BOOL UnlockFirstThunk(PIMAGE_IMPORT_DESCRIPTOR pImp)
{
    PIMAGE_THUNK_DATA t = (PIMAGE_THUNK_DATA)(VA(pImp->FirstThunk));

    SIZE_T count = 0;
    while (t[count].u1.Function != 0)
        count++;

    SIZE_T pBytes = count * sizeof(IMAGE_THUNK_DATA);
    DWORD pOldProt = 0;
    return VirtualProtect(t, pBytes, PAGE_READWRITE, &pOldProt);
}

BOOL patchFirstThunk (PIMAGE_IMPORT_DESCRIPTOR pImportDesc, PIMAGE_THUNK_DATA pFirstThunk, ULONGLONG newAddr)
{
    if (UnlockFirstThunk(pImportDesc) == 0)
    {
        DWORD r = GetLastError();
        printf("Unlocking FirstThunk memory for writing failed.\n Error: %d\n", r);
        return FALSE;
    }
    pFirstThunk->u1.Function = newAddr;
    return TRUE;
}

#define UNLOCK_FAILED -1

/**
 * @brief Find the func's address in FirstThunk, replace with newAddr. Can by retrieved by ordinal as well (TODO).
 * @param pImportDesc import descriptor containing function addresses to be patched
 * @param funcAddr adddress of function to patch
 * @param newAddr address pointed to by original function after patching
 * @return int number of patched FirstThunks or -1 on error
 */
int patchThunksOfFunc(PIMAGE_IMPORT_DESCRIPTOR pImportDesc, ULONGLONG funcAddr, ULONGLONG newAddr)
{
    unsigned int patchedCnt = 0;
    // int i = 1;
    // puts("Thunk BEGIN");
    // printf("Searched address: %lld\n", funcAddr);
    for (PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(VA(pImportDesc->FirstThunk));
        pFirstThunk->u1.Function != 0ULL; ++pFirstThunk)
    {
        // printf("%d. %lld", i, pFirstThunk->u1.Function);
        if (funcAddr == pFirstThunk->u1.Function)
        {
            if (! patchFirstThunk(pImportDesc, pFirstThunk, newAddr))
                return UNLOCK_FAILED;
            patchedCnt++;
            // printf("------>%lld", newAddr);
        }
        // puts("");
        // ++i;
    }
    // puts("Thunk END");
    return patchedCnt;
}

/**
 * @brief Find all PIMAGE_IMPORT_DESCRIPTORs importing a function of given name and patch
 * their FirstThunks (found by address), using newAddr address.
 * 
 * 
 * Each imported .dll is represented by a single IMAGE_IMPORT_DESCRIPTOR.
 * Each FirstThunk points to a segment of IAT belonging to given .dll
 * 
 * @param funcName name of searched function
 * @param funcImpDescs (out param) pointer to an arry of PIMAGE_IMPORT_DESCRIPTORs 
 * @param importedDuplicatesMax length of funcImpDescs array
 * @return int number of found import descriptiors
 */
int patchThunks(char *funcName, ULONGLONG funcAddr, ULONGLONG newAddr)
{
    unsigned int patchedCnt = 0;
    // iterate dlls
    for (PIMAGE_IMPORT_DESCRIPTOR pImportDesc = getFirstImpDesc();
         pImportDesc->Characteristics != 0; ++pImportDesc)
    {
        // iterate dll's imported functions
        for (PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(VA(pImportDesc->OriginalFirstThunk));
             pOriginalFirstThunk->u1.AddressOfData != 0; ++pOriginalFirstThunk)
        {
            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(VA(pOriginalFirstThunk->u1.AddressOfData));
            // find searched function by name
            if (strncmp(funcName, pImportByName->Name, 6) == 0)
            {
                // .dll contains searched function, patch all FirstThunks matching its address
                int ret = patchThunksOfFunc(pImportDesc, funcAddr, newAddr);
                if (ret == UNLOCK_FAILED)
                    return UNLOCK_FAILED;
                patchedCnt += ret;
            }
        }
    }
    return patchedCnt;
}



BOOL replaceFunc(char *funcName, ULONGLONG funcAddr, ULONGLONG pNewFunc)
{
    int r = patchThunks(funcName, funcAddr, pNewFunc);
    if (r == UNLOCK_FAILED)
        return FALSE;
    if (r == 0) {
        puts("No FirstThunks patched.");
        return FALSE;
    }
    return TRUE;
}

// function pointer declaration
// ============================
// RETURN_TYPE (*FUNCTION_NAME)(ARG1_TYPE, ARG2_TYPE, ...);

void *(*g_OrigMalloc)(size_t) = NULL;          // void * malloc(size)
void *(*g_OrigCalloc)(size_t, size_t) = NULL;  // void * calloc(count, size)
void *(*g_OrigRealloc)(void *, size_t) = NULL; // void * calloc(ptr, newSize)
void (*g_OrigFree)(void *) = NULL;             // void   free (ptr)

#define ALLOCATIONS_MAX 50

uintptr_t g_AllocatedMemory[ALLOCATIONS_MAX] = {0};
size_t g_AllocatedMemorySize[ALLOCATIONS_MAX] = {0};
size_t g_AllocCnt = 0;

/**
 * loguju:
 * 1. pamat sa alokovala
 * 2. velkost alokovanej pamate
 */
void *MallocDebug_malloc(size_t size)
{
    if (g_AllocCnt >= ALLOCATIONS_MAX)
    {
        puts("Maximum allocations reached, not allocating anything.");
        return NULL;
    }

    void *ptr = g_OrigMalloc(size);
    g_AllocatedMemory[g_AllocCnt] = (uintptr_t)ptr;
    g_AllocatedMemorySize[g_AllocCnt++] = size;

    printf("Allocated %zu bytes @%p\n", size, ptr);
    return ptr;
}

/**
 * Budou záznam [alokace] rušit
 * stěžovat si, pokud by měly zrušit neznámou,
 * nebo uz dříve zrušenou alokaci
 */
void MallocDebug_free(void *ptr)
{
    for (size_t i = 0; i < ALLOCATIONS_MAX; ++i)
    {
        if (g_AllocatedMemory[i] == (uintptr_t)ptr)
        {
            g_AllocatedMemory[i] = 0;
            g_AllocatedMemorySize[i] = 0;
            --g_AllocCnt;
            g_OrigFree(ptr);
            printf("Freed memory @%p\n", ptr);
            return;
        }
    }

    printf("Requested memory @(%p) isn't allocated\n- already freed or never allocated within revgrind init & done block.\n", ptr);
}
/**
 * @brief Allocates an array in memory with elements initialized to 0.
 *
 * @param number number of elements
 * @param size length in bytes of each element
 * @return void* pointer to allocated space
 */
void *MallocDebug_calloc(size_t number, size_t size)
{
    if (g_AllocCnt >= ALLOCATIONS_MAX)
    {
        printf("Maximum allocations of %d reached, not allocating anything.\n", ALLOCATIONS_MAX);
        return NULL;
    }

    if (size <= 0 || number <= 0)
        return NULL; // in microsoft implementation this would actually be undefined behavior

    void *buf = g_OrigMalloc(number * size);
    g_AllocatedMemory[g_AllocCnt] = (uintptr_t)buf;
    g_AllocatedMemorySize[g_AllocCnt++] = size;

    memset(buf, 0, number * size);
    return buf;
}

/**
realloc returns a void pointer to the reallocated (and possibly moved) memory block.

If there isn't enough available memory to expand the block to the given size,
the original block is left unchanged, and NULL is returned.

If size is zero, then the block pointed to by memblock is freed; the return value is NULL,
and memblock is left pointing at a freed block.

The return value points to a storage space that is suitably aligned for storage of any type of object.
To get a pointer to a type other than void, use a type cast on the return value.*
*/
void *MallocDebug_realloc(void *memblock, size_t size)
{
    // allow reallocation (enlargmenet of an existing array) when max allocations have been reached,
    // but do not allow surpassing the max allocations amount
    if (g_AllocCnt >= ALLOCATIONS_MAX && memblock == NULL)
    {
        printf("Maximum allocations of %d reached, not allocating anything.\n", ALLOCATIONS_MAX);
        return NULL;
    }
    if (size <= 0)
    {
        MallocDebug_free(memblock);
        return NULL;
    }

    void *newMem = g_OrigMalloc(size);
    if (newMem == NULL)
    {
        puts("Not enough space on the heap for new allocations.");
        return NULL;
    }
    if (memblock)
    {
        // if new requested size < current size then copy only what fits now
        memcpy_s(newMem, size, memblock, min(size, _msize(memblock)));
    }
    g_AllocatedMemory[g_AllocCnt] = (uintptr_t)newMem;
    g_AllocatedMemorySize[g_AllocCnt++] = size;

    if (memblock)
        MallocDebug_free(memblock);
    return newMem;
}
/**
 * Najde v IAT pozici funkcí malloc, calloc, realloc
 * a free a změní jejich adresu na adresy substitučních funkcí
 */
BOOL MallocDebug_Init(void)
{
    if (g_OrigMalloc != NULL)
    { // or other func is not NULL
        puts("Init already called - not doing anything.");
        return FALSE;
    }
    // backup original function addresses
    g_OrigMalloc = &malloc;
    g_OrigCalloc = &calloc;
    g_OrigRealloc = &realloc;
    g_OrigFree = &free;

    // todo: replace ULL with something more proper
    if (!replaceFunc("malloc", (ULONGLONG)g_OrigMalloc, (ULONGLONG)MallocDebug_malloc))
    {
        puts("Patching malloc failed.");
        return FALSE;
    }
    if (!replaceFunc("calloc", (ULONGLONG)g_OrigCalloc, (ULONGLONG)MallocDebug_calloc))
    {
        puts("Patching calloc failed.");
        return FALSE;
    }
    if (!replaceFunc("realloc", (ULONGLONG)g_OrigRealloc, (ULONGLONG)MallocDebug_realloc))
    {
        puts("Patching realloc failed.");
        return FALSE;
    }
    if (!replaceFunc("free", (ULONGLONG)g_OrigFree, (ULONGLONG)MallocDebug_free))
    {
        puts("Patching free failed.");
        return FALSE;
    }
    puts("+++++++++++++++++++++++++++++++++++++++");
    puts("revgrind init");
    puts("+++++++++++++++++++++++++++++++++++++++");
    assert(g_OrigMalloc != &malloc);
    return TRUE;
}

/**
 * Vrátí IAT do původního stavu a vypíše případné zbytky tabulky,
 * které budou považovány za memory leaky :)
 */
BOOL MallocDebug_Done(void)
{
    if (g_OrigMalloc == NULL)
    {
        puts("Done called but revgrind hasn't been initialised.");
        return FALSE;
    }

    // restore original IAT state
    // replace malloc (now Debug_malloc) with gOrigMalloc (malloc), etc.
    if (!replaceFunc("malloc", (ULONGLONG)malloc, (ULONGLONG)g_OrigMalloc))
    {
        puts("Restoring malloc failed.");
        return FALSE;
    }
    g_OrigMalloc = NULL;
    if (!replaceFunc("calloc", (ULONGLONG)calloc, (ULONGLONG)g_OrigCalloc))
    {
        puts("Restoring calloc failed.");
        return FALSE;
    }
    g_OrigCalloc = NULL;
    if (!replaceFunc("realloc", (ULONGLONG)realloc, (ULONGLONG)g_OrigRealloc))
    {
        puts("Restoring realloc failed.");
        return FALSE;
    }
    g_OrigRealloc = NULL;
    if (!replaceFunc("free", (ULONGLONG)free, (ULONGLONG)g_OrigFree))
    {
        puts("Restoring free failed.");
        return FALSE;
    }
    g_OrigFree = NULL;
    
    puts("Original IAT restored.");

    // print memory leaks
    if (g_AllocCnt != 0)
    {
        puts("Memory leaks:");
        for (size_t i = 0; i < ALLOCATIONS_MAX; ++i)
        {
            if (g_AllocatedMemorySize[i] != 0)
            {
                printf("\tLeaked %zu bytes @%p\n", g_AllocatedMemorySize[i], (void *)g_AllocatedMemory[i]);
            }
        }
    }
    else
    {
        puts("No memory leaked.");
    }
    // todo not sure if i want to clean this up?
    // zero g_AllocatedMemory
    // zero g_AllocatedMemorySize
    // g_AllocCnt = 0;
    puts("---------------------------------------");
    puts("revgrind done");
    puts("---------------------------------------");
    return TRUE;
}

void printArr(int *arr, size_t size)
{
    for (int i = 0; i < size; ++i)
        printf("%d ", arr[i]);
    printf("\n");
}

int testReallocFree(void)
{
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    const int arrSize = 4;
    int *buf = (int *)malloc(arrSize * sizeof(int));

    assert (_msize(buf) == arrSize * sizeof(int));
    
    for (int i = 0; i < arrSize; ++i)
        buf[i] = i;
    printArr(buf, arrSize);

    const int newArrSize = 0;
    int *oldbuf = buf;
    buf = (int *)realloc(buf, newArrSize * sizeof(int));
    if (buf != NULL)
    {
        if ( ! MallocDebug_Done() )
            return 0;
        return 0;
    }
    if ( ! MallocDebug_Done() )
        return 0;
    return 1;
}

int testRealloc(void)
{
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    const int arrSize = 4;
    int *buf = (int *)malloc(arrSize * sizeof(int));

    assert (_msize(buf) == arrSize * sizeof(int));
    printf("buf size: %zu\n", _msize(buf));
    for (int i = 0; i < arrSize; ++i)
        buf[i] = i;
    printArr(buf, arrSize);

    const int newArrSize = 2 * arrSize;
    int *oldbuf = buf;
    buf = (int *)realloc(buf, newArrSize * sizeof(int));

    assert (_msize(buf) == newArrSize * sizeof(int));
    printf("buf newsize: %zu\n", _msize(buf));
    for (int i = arrSize; i < newArrSize; ++i)
        buf[i] = i;
    printArr(buf, newArrSize);

    assert (oldbuf != buf);

    free(buf);

    if ( ! MallocDebug_Done() )
        return 0;
    return 1;
}

int testReallocNew(void)
{
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    const int size = 2;
    int *buf = NULL;
    buf = (int *)realloc(buf, size * sizeof(int));

    assert (_msize(buf) == size * sizeof(int));

    for (int i = 0; i < size; ++i)
        buf[i] = i;
    printArr(buf, size);

    free(buf);

    if ( ! MallocDebug_Done() )
        return 0;
    return 1;
}

int testCallocNormal(void)
{
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    const int size = 9;
    int *buf = calloc(size, sizeof(int));

    assert (_msize(buf) == size * sizeof(int));

    printArr(buf, size);

    for (size_t i = 0; i < size; ++i)
        buf[i] = i;
    printArr(buf, size);

    free(buf);
    if ( ! MallocDebug_Done() )
        return 0;
    return 1;
}

int testCallocLeak(void)
{
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }
    const int size = 9;
    int *buf = calloc(size, sizeof(int));

    assert (_msize(buf) == size * sizeof(int));

    printArr(buf, size);
    if ( ! MallocDebug_Done() )
        return 0;
    return 1;
}

int main(void)
{
    assert(testRealloc() == 1);
    assert(testReallocNew() == 1);
    assert(testReallocFree() == 1);
    assert(testCallocNormal() == 1);
    assert(testCallocLeak() == 1);
    return EXIT_SUCCESS;
}
