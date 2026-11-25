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

// static BOOL UnlockFirstThunk(PIMAGE_IMPORT_DESCRIPTOR pImp)
// {
//     PIMAGE_THUNK_DATA t = (PIMAGE_THUNK_DATA)(VA(pImp->FirstThunk));

//     SIZE_T count = 0;
//     while (t[count].u1.Function != 0)
//         count++;

//     SIZE_T pBytes = count * sizeof(IMAGE_THUNK_DATA);
//     DWORD pOldProt = 0;
//     return VirtualProtect(t, pBytes, PAGE_READWRITE, &pOldProt);
// }

BOOL patchFirstThunk(PIMAGE_IMPORT_DESCRIPTOR pImportDesc, PIMAGE_THUNK_DATA pFirstThunk, ULONGLONG newAddr)
{    
    pFirstThunk->u1.Function = newAddr;
    // test if IAT's not already unlocked for writing
    __try {
        // patch function
        pFirstThunk->u1.Function = newAddr;
    }
    // todo should ideally only catch read violations
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // not unlocked,
        // unlock thunk for writing
        PIMAGE_THUNK_DATA t = (PIMAGE_THUNK_DATA)(VA(pImportDesc->FirstThunk));
        SIZE_T count = 0;
        while (t[count].u1.Function != 0)
            count++;

        SIZE_T pBytes = count * sizeof(IMAGE_THUNK_DATA);
        DWORD pOldProt = 0;
        if (!VirtualProtect(t, pBytes, PAGE_READWRITE, &pOldProt))
        {
            DWORD r = GetLastError();
            printf("Unlocking FirstThunk memory for writing failed.\n Error: %d\n", r);
            return FALSE;
        }
        // patch function
        pFirstThunk->u1.Function = newAddr;

        // restore thunk permissions
        DWORD rePerms = 0;
        if (!VirtualProtect(t, pBytes, pOldProt, &rePerms))
        {
            DWORD r = GetLastError();
            printf("Unlocking FirstThunk memory for writing failed.\n Error: %d\n", r);
            return FALSE;
        }
    }

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
            if (!patchFirstThunk(pImportDesc, pFirstThunk, newAddr))
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
            if (strcmp(funcName, pImportByName->Name) == 0)
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
    if (r == 0)
    {
        puts("No FirstThunks patched.");
        return FALSE;
    }
    return TRUE;
}

// function pointer declaration
// ============================
// RETURN_TYPE (*FUNCTION_NAME)(ARG1_TYPE, ARG2_TYPE, ...);

typedef void *(*MallocFun)(size_t size);
typedef void *(*CallocFun)(size_t count, size_t size);
typedef void *(*ReallocFun)(void *block, size_t newSize);
typedef void (*FreeFun)(void *block);

static MallocFun g_OrigMalloc = NULL;
static CallocFun g_OrigCalloc = NULL;
static ReallocFun g_OrigRealloc = NULL;
static FreeFun g_OrigFree = NULL;

#define ALLOCATIONS_MAX 50

ULONG_PTR g_AllocatedMemory[ALLOCATIONS_MAX] = {0};
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
    if (!ptr) 
    {
        puts("Not enough space on the heap for new allocations.");
        return NULL;  
    }
    g_AllocatedMemory[g_AllocCnt] = (ULONG_PTR)ptr;
    g_AllocatedMemorySize[g_AllocCnt++] = size;

    printf("Allocated %zu bytes @%p\n", size, ptr);
    return ptr;
}

// remove memory from the DEBUG representation
BOOL removeMem(void* memblock)
{
    for (size_t i = 0; i < ALLOCATIONS_MAX; ++i)
    {
        if (g_AllocatedMemory[i] == (ULONG_PTR) memblock)
        {
            g_AllocatedMemory[i] = 0;
            g_AllocatedMemorySize[i] = 0;
            --g_AllocCnt;
            return TRUE;
        }
    }

    printf("Requested memory @(%p) isn't allocated\n\
        - already freed or never allocated within revgrind init & done block.\n", memblock);
    return FALSE;
}

/**
 * Budou záznam [alokace] rušit
 * stěžovat si, pokud by měly zrušit neznámou,
 * nebo uz dříve zrušenou alokaci
 */
void MallocDebug_free(void *ptr)
{
    printf("Freeing memory @%p\n", ptr);
    if (! removeMem(ptr))
        exit(1);
    g_OrigFree(ptr);
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
    /*
    In the Microsoft implementation, if number or size is zero,
    calloc returns a pointer to an allocated block of non-zero size.
    An attempt to read or write through the returned pointer leads to undefined behavior.

    note: still want to make an entry in mem representation
    */
    if (size == 0 || number == 0)
        puts("Calloc called with either of args equal to 0, read or write to returned mem is UB");

    void *buf = g_OrigCalloc(number, size);
    
    if (buf == NULL)
    {
        puts("Not enough space on the heap for new allocations.");
        return NULL;
    }
    
    printf("Allocated memory @%p\n", buf);
    g_AllocatedMemory[g_AllocCnt] = (ULONG_PTR)buf;
    g_AllocatedMemorySize[g_AllocCnt++] = size * number;

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

tldr 4 cases:
1. reallocate existing memory (memblock != NULL && size != 0)
2. free existing memory       (memblock != NULL && size == 0)
3. allocate new memory        (memblock == NULL && size != 0)
4. implementation dependant   (memblock == NULL && size == 0)
    - this sometimes allocates length zero mem that needs freeing,
      sometimes returns NULL (doesn't need freeing)
*/
void *MallocDebug_realloc(void *memblock, size_t size)
{
    // allow reallocation (enlargmenet of an existing array) when max allocations have been reached,
    // but do not allow allocating previously unalloced memory (thus surpassing the max allocations amount)
    
    // 1. reallocate existing memory (memblock != NULL && size != 0)
    // 2. free existing memory       (memblock != NULL && size == 0)
    // 3. allocate new memory        (memblock == NULL && size != 0)
    // 4. implementation dependant   (memblock == NULL && size == 0)
    // match on all except free
    if (size >= 0 && g_AllocCnt >= ALLOCATIONS_MAX && memblock == NULL)
    {
        printf("Maximum allocations of %d reached, not allocating anything.\n", ALLOCATIONS_MAX);
        return NULL;
    }

    void *newMem = g_OrigRealloc(memblock, size);

    if (newMem == NULL && size != 0) // in case size == 0, we're expecting exactly NULL
    {
        puts("Not enough space on the heap for new allocations.");
        return NULL;
    }
    
    // case 4, realloc has allocated a zero length memory block, warn the user
    if (newMem && memblock == NULL && size == 0)
        puts("realloc has allocated a zero length memory block, writing and reading it may crash the program.");
    
    // 1. reallocate existing memory (memblock != NULL && size != 0)
    // 2. free existing memory       (memblock != NULL && size == 0)
    // 3. allocate new memory        (memblock == NULL && size != 0)
    // 4. implementation dependant   (memblock == NULL && size == 0)
    // match relocation and freeing
    // remove block from memory representation
    if (memblock != NULL) {
        BOOL r = FALSE;
        r = removeMem(memblock);
        if (!r) {
            puts("Memory representation inconsisnent.");
            exit(1);
        }
    }

    // debug printouts
    if (memblock && size) // memblock == NULL means we're allocating new memory
        printf("Reallocated memory @%p->%p\n", memblock, newMem);
    else if (memblock != NULL && size == 0)
        printf("Realloc is freeing memory @%p\n", memblock);
    else
        printf("Allocated memory @%p of size %zu\n", newMem, size);
    
    // 1. reallocate existing memory (memblock != NULL && size != 0)
    // 2. free existing memory       (memblock != NULL && size == 0)
    // 3. allocate new memory        (memblock == NULL && size != 0)
    // 4. implementation dependant   (memblock == NULL && size == 0)
    // match every case except freeing memory AND check 4. case if this impl. returned non-NULL
    if ((! (memblock != NULL && size == 0) ) && newMem)
    {
        g_AllocatedMemory[g_AllocCnt] = (ULONG_PTR)newMem;
        g_AllocatedMemorySize[g_AllocCnt++] = size;
    }

    return newMem;
}

/**
 * @brief Iterate OFT & FT in parallel, return funcAddr fetched by name in OFT.
 *
 * @param funcName name of searched functions
 * @param len function name length in chars without \0
 * @return function addr or 0 when not found or when PE malformed.
 */
ULONG_PTR getFuncAddr(char *funcName)
{
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = getFirstImpDesc();
    // iterate import descriptors (dlls)
    for (; pImportDesc->Name && pImportDesc->FirstThunk; ++pImportDesc)
    {
        // import address table (IAT)
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(VA(pImportDesc->FirstThunk));
        // import name table (INT)
        PIMAGE_THUNK_DATA nt = pImportDesc->OriginalFirstThunk
                                   ? (PIMAGE_THUNK_DATA)(VA(pImportDesc->OriginalFirstThunk))
                                   : NULL;
        // no INT: only the address iat[i].u1.Function is available,
        // continue with the next import descriptor
        if (!nt)
            continue; // no INT: names unavailable for this DLL

        for (size_t i = 0; iat[i].u1.Function != 0; i++)
        {

            if (nt[i].u1.AddressOfData == 0)
            {
                puts("INT shorter than IAT: PE malformed. Stopping...");
                return 0;
            }

            if (IMAGE_SNAP_BY_ORDINAL(nt[i].u1.Ordinal))
            {
                // ignore ordinal imports
                // WORD ord = (WORD)IMAGE_ORDINAL(nt[i].u1.Ordinal);
                // printf("#%u -> %p\n", ord, (void *)iat[i].u1.Function);
                continue;
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)(VA(nt[i].u1.AddressOfData));
                // printf("%s -> %p\n", ibn->Name, (void *)iat[i].u1.Function);
                if (strcmp(funcName, ibn->Name) == 0)
                    return iat[i].u1.Function;
            }
        }
    }
    return 0;
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
    // todo: if fun not used, it stays null, which is ok?
    g_OrigMalloc = (MallocFun)getFuncAddr("malloc");
    g_OrigCalloc = (CallocFun)getFuncAddr("calloc");
    g_OrigRealloc = (ReallocFun)getFuncAddr("realloc");
    g_OrigFree = (FreeFun)getFuncAddr("free");

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
        BOOL allZero = TRUE;
        for (size_t i = 0; i < ALLOCATIONS_MAX; ++i)
        {
            if (g_AllocatedMemorySize[i] != 0)
            {
                allZero = FALSE;
                printf("\tLeaked %zu bytes @%p\n", g_AllocatedMemorySize[i], (void *)g_AllocatedMemory[i]);
            }
        }
        if (allZero)
            puts("Memory leak of length 0 occurred.");
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
    puts("testReallocFree");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    const int arrSize = 4;
    int *buf = (int *)malloc(arrSize * sizeof(int));

    for (int i = 0; i < arrSize; ++i)
        buf[i] = i;
    printArr(buf, arrSize);

    const int newArrSize = 0;
    int *tmp = NULL;
    tmp = (int *)realloc(buf, newArrSize * sizeof(int));
    if (tmp != NULL)
    {
        if (!MallocDebug_Done())
            return 0;
        return 0;
    }
    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int testRealloc(void)
{
    puts("testRealloc");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    const int arrSize = 4;
    int *buf = (int *)malloc(arrSize * sizeof(int));
    
    assert (buf);
    
    for (int i = 0; i < arrSize; ++i)
        buf[i] = i;
    printArr(buf, arrSize);

    const int newArrSize = 2 * arrSize;
    int *tmp = NULL;
    tmp = (int *)realloc(buf, newArrSize * sizeof(int));
    
    assert (tmp != NULL); // should free buf here if tmp == NULL (realloc failed)
    buf = tmp;

    for (int i = arrSize; i < newArrSize; ++i)
        buf[i] = i;
    printArr(buf, newArrSize);

    free(buf);

    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int testReallocNew(void)
{
    puts("testReallocNew");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    const int size = 2;
    int *buf = NULL;
    buf = (int *)realloc(buf, size * sizeof(int));
    
    assert (buf != NULL);

    for (int i = 0; i < size; ++i)
        buf[i] = i;
    printArr(buf, size);

    free(buf);

    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int testReallocZero(void)
{
    puts("testReallocZero");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    puts("Allocating 0 length buffer");
    int * buf = (int *)realloc(NULL, 0);
    
    assert (buf != NULL);

    free(buf);

    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int testReallocZeroLeak(void)
{
    puts("testReallocZeroLeak");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    puts("Allocating 0 length buffer");
    int * buf = (int *)realloc(NULL, 0);
    
    assert (buf != NULL);

    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int testReallocZeroReallocAgain(void)
{
    puts("testReallocZeroReallocAgain");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    puts("Allocating 0 length buffer");
    int * buf = (int *)realloc(NULL, 0);
    
    assert (buf != NULL);

    puts("Reallocating 0 length buffer into a larger one");
    const int arrSize = 8;
    int * tmp = NULL;
    tmp = (int *)realloc(buf, arrSize * sizeof(int));
    assert (tmp != NULL);
    buf = tmp;
    
    for (int i = 0; i < arrSize; ++i)
        buf[i] = i;
    printArr(buf, arrSize);

    free(buf);

    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int testCallocNormal(void)
{
    puts("testCallocNormal");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }

    const int size = 9;
    int *buf = calloc(size, sizeof(int));

    printArr(buf, size);

    for (size_t i = 0; i < size; ++i)
        buf[i] = i;
    printArr(buf, size);

    free(buf);
    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int testCallocLeak(void)
{
    puts("testCallocLeak");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }
    const int size = 9;
    int *buf = calloc(size, sizeof(int));

    printArr(buf, size);
    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int main(void)
{
    // void *(*g_OrigMalloc)(size_t) = NULL;          // void * malloc(size)
    // printf("%p\n%p\n", g_OrigMalloc, malloc);
    assert(testRealloc() == 1);
    assert(testReallocNew() == 1);
    assert(testReallocFree() == 1);
    assert(testReallocZero() == 1);
    assert(testReallocZeroLeak() == 1);
    assert(testReallocZeroReallocAgain() == 1);

    assert(testCallocNormal() == 1);
    assert(testCallocLeak() == 1);
    return EXIT_SUCCESS;
}
