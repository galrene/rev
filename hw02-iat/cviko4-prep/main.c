#include <stdio.h>
#include <string.h>
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
*/

// convert relative virtual address to virtual address (absolute address in memory)
static void *VA(ULONG_PTR rva)
{
    static BYTE *base;
    if (!base)
    {
        base = (BYTE *)GetModuleHandle(NULL);
    }
    return base + rva;
}

PIMAGE_IMPORT_DESCRIPTOR getFirstImpDesc(void)
{
    HMODULE hPEFile = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(VA(pDosHeader->e_lfanew));

    IMAGE_DATA_DIRECTORY *dir =
        &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->VirtualAddress == 0 || dir->Size == 0)
        return 0;   // no imports
    
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)VA(dir->VirtualAddress);
    return pImportDesc;
}

PIMAGE_IMPORT_DESCRIPTOR getImpDescEnd(void)
{
    HMODULE hPEFile = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(VA(pDosHeader->e_lfanew));
    
    IMAGE_DATA_DIRECTORY *dir =
        &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->VirtualAddress == 0 || dir->Size == 0)
        return 0;   // no imports
    
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)VA(dir->VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescEnd = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)pImportDesc + dir->Size);
    return pImportDescEnd;
}

BOOL patchFirstThunk(PIMAGE_IMPORT_DESCRIPTOR pImportDesc, PIMAGE_THUNK_DATA pFirstThunk, ULONG_PTR newAddr)
{    
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
 * @brief Find the func's address in FirstThunk, replace with newAddr.
 * @param pImportDesc import descriptor containing function addresses to be patched
 * @param funcAddr adddress of function to patch
 * @param newAddr address pointed to by original function after patching
 * @return int number of patched FirstThunks or -1 on error
 */
int patchThunksOfFunc(PIMAGE_IMPORT_DESCRIPTOR pImportDesc, ULONG_PTR funcAddr, ULONG_PTR newAddr)
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
int patchThunks(char *funcName, ULONG_PTR funcAddr, ULONG_PTR newAddr)
{
    unsigned int patchedCnt = 0;
    // iterate dlls
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = getFirstImpDesc();
    PIMAGE_IMPORT_DESCRIPTOR pImportDescEnd = getImpDescEnd();

    for (; pImportDesc + 1 <= pImportDescEnd && pImportDesc->Name && pImportDesc->FirstThunk; ++pImportDesc)
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

BOOL replaceFunc(char *funcName, ULONG_PTR funcAddr, ULONG_PTR pNewFunc)
{
    int r = patchThunks(funcName, funcAddr, pNewFunc);
    if (r == UNLOCK_FAILED)
        return FALSE;
    if (r == 0)
    {
        printf("No FirstThunks for %s to be patched found.\n", funcName);
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
BOOL g_RevgrindInitialised = FALSE;

BOOL isTracked(void * memblock)
{
    if (! memblock)
        return FALSE;
    for (size_t i = 0; i < ALLOCATIONS_MAX; ++i)
    {
        if (g_AllocatedMemory[i] == (ULONG_PTR)memblock)
        {
            return TRUE;
        }
    }
    return FALSE;
}

// find first free slot and add to to the debug memory representation
// returns true on success, false on table full
BOOL addMem(void* memblock, size_t size)
{
    for (size_t i = 0; i < ALLOCATIONS_MAX; ++i)
    {

        if (g_AllocatedMemory[i] == 0)
        {
            g_AllocatedMemory[i] = (ULONG_PTR)memblock;
            g_AllocatedMemorySize[i] = size;
            ++g_AllocCnt;
            return TRUE;
        }
    }
    return FALSE;
}

// remove memory from the DEBUG representation
BOOL removeMem(void* memblock)
{
    if (memblock == NULL)
    {
        return FALSE;
    }

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

    return FALSE;
}

/**
 * loguju:
 * 1. pamat sa alokovala
 * 2. velkost alokovanej pamate
 */
void *MallocDebug_malloc(size_t size)
{
    void *ptr = g_OrigMalloc(size);
    if (!ptr) 
    {
        puts("Not enough space on the heap for new allocations.");
        return NULL;  
    }
    if (! addMem(ptr, size))
    {
        printf("Maximum debug allocations reached, not tracking block @%p.\n", ptr);
    }

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
    printf("Freeing memory @%p\n", ptr);
    if (ptr)
    {
        if ( ! removeMem(ptr) )
            printf("Requested memory @(%p) isn't allocated\n\
            - already freed or never allocated within revgrind init & done block.\n", ptr);
    }
    g_OrigFree(ptr);
}
/**
 * @brief Allocates an array in memory with elements initialized to 0.
 *
 * @param number number of elements
 * @param size length in bytes of each element
 * @return void* pointer to allocated space
 * 
 * 
 * cases:
 * 1. (number = 0, size = 0)
 * 2. (number = 0, size > 0)
 * 3. (number > 0, size = 0) 
 * 1 - 3: In the Microsoft implementation, if number or size is zero, calloc returns
 * a pointer to an allocated block of non-zero size.
 * An attempt to read or write through the returned pointer leads to undefined behavior.
 * 
 * 4. (number > 0, size > 0) standard operation
 */
void *MallocDebug_calloc(size_t number, size_t size)
{
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
    if (! addMem(buf, size * number))
    {
        printf("Maximum debug allocations reached, not tracking block @%p.\n", buf);
    }

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
    if (memblock && !isTracked(memblock))
        printf("Realloc of an untracked block @%p, may crash.\n", memblock);
    
    void *newMem = g_OrigRealloc(memblock, size);

    if (newMem == NULL && size != 0) // in case size == 0, we're expecting exactly NULL
    {
        puts("Not enough space on the heap for new allocations.");
        return NULL;
    }
    
    // case 4, realloc has allocated a zero length memory block, warn the user
    if (newMem && !memblock && size == 0)
        puts("realloc has allocated a zero length memory block, writing and reading it may crash the program.");
    
    // 1. reallocate existing memory (memblock != NULL && size != 0)
    // 2. free existing memory       (memblock != NULL && size == 0)
    // 3. allocate new memory        (memblock == NULL && size != 0)
    // 4. implementation dependant   (memblock == NULL && size == 0)
    // match relocation and freeing
    // remove block from memory representation
    if (memblock)
        removeMem(memblock);

    // debug printouts
    if (memblock && size) // memblock == NULL means we're allocating new memory
        printf("Reallocated memory @%p->%p\n", memblock, newMem);
    else if (memblock != NULL && size == 0)
        printf("Realloc is freeing memory @%p\n", memblock);
    else
        printf("Allocated memory @%p of size %zu\n", newMem, size);
    
    // log all non-NULL returns
    if (newMem && !addMem(newMem, size))
    {
        printf("Maximum debug allocations reached, not tracking block @%p.\n", newMem);
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
    PIMAGE_IMPORT_DESCRIPTOR pImportDescEnd = getImpDescEnd();
    // iterate import descriptors (dlls)
    for (; pImportDesc + 1 <= pImportDescEnd && pImportDesc->Name && pImportDesc->FirstThunk; ++pImportDesc)
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
                puts("INT shorter than IAT. Malformed, skipping import descriptor.");
                break;
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
    if (g_RevgrindInitialised == TRUE)
    { // or other func is not NULL
        puts("Init already called - not doing anything.");
        return FALSE;
    }
    g_RevgrindInitialised = TRUE;

    // backup original function addresses
    g_OrigMalloc = (MallocFun)getFuncAddr("malloc");
    g_OrigCalloc = (CallocFun)getFuncAddr("calloc");
    g_OrigRealloc = (ReallocFun)getFuncAddr("realloc");
    g_OrigFree = (FreeFun)getFuncAddr("free");

    // patch only functions whose original was found in the IAT,
    // so MallocDebug_* never calls a NULL g_Orig*
    if (!g_OrigMalloc)
        puts("malloc not found in IAT, not patching it.");
    else if (!replaceFunc("malloc", (ULONG_PTR)g_OrigMalloc, (ULONG_PTR)MallocDebug_malloc))
        puts("Malloc not patched.");

    if (!g_OrigCalloc)
        puts("calloc not found in IAT, not patching it.");
    else if (!replaceFunc("calloc", (ULONG_PTR)g_OrigCalloc, (ULONG_PTR)MallocDebug_calloc))
        puts("Calloc not patched.");

    if (!g_OrigRealloc)
        puts("realloc not found in IAT, not patching it.");
    else if (!replaceFunc("realloc", (ULONG_PTR)g_OrigRealloc, (ULONG_PTR)MallocDebug_realloc))
        puts("Realloc not patched.");

    if (!g_OrigFree)
        puts("free not found in IAT, not patching it.");
    else if (!replaceFunc("free", (ULONG_PTR)g_OrigFree, (ULONG_PTR)MallocDebug_free))
        puts("Free not patched.");
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
    if (g_RevgrindInitialised == FALSE)
    {
        puts("Done called but revgrind hasn't been initialised.");
        return FALSE;
    }

    // restore original IAT state:
    // swap every IAT entry Init pointed at MallocDebug_* back to the original.
    // skip functions that Init never patched (original not found)
    BOOL allRestored = TRUE;
    if (g_OrigMalloc)
    {
        if (!replaceFunc("malloc", (ULONG_PTR)MallocDebug_malloc, (ULONG_PTR)g_OrigMalloc))
        {
            puts("Malloc not restored.");
            allRestored = FALSE;
        }
        g_OrigMalloc = NULL;
    }
    if (g_OrigCalloc)
    {
        if (!replaceFunc("calloc", (ULONG_PTR)MallocDebug_calloc, (ULONG_PTR)g_OrigCalloc))
        {
            puts("Calloc not restored.");
            allRestored = FALSE;
        }
        g_OrigCalloc = NULL;
    }
    if (g_OrigRealloc)
    {
        if (!replaceFunc("realloc", (ULONG_PTR)MallocDebug_realloc, (ULONG_PTR)g_OrigRealloc))
        {
            puts("Realloc not restored.");
            allRestored = FALSE;
        }
        g_OrigRealloc = NULL;
    }
    if (g_OrigFree)
    {
        if (!replaceFunc("free", (ULONG_PTR)MallocDebug_free, (ULONG_PTR)g_OrigFree))
        {
            puts("Free not restored.");
            allRestored = FALSE;
        }
        g_OrigFree = NULL;
    }

    if (allRestored)
        puts("Original IAT restored.");
    else
        puts("Original IAT only partially restored.");

    // print memory leaks
    if (g_AllocCnt != 0)
    {
        puts("Memory leaks:");
        for (size_t i = 0; i < ALLOCATIONS_MAX; ++i)
        {
            if (g_AllocatedMemory[i] != 0)
            {
                printf("\tLeaked %zu bytes @%p\n", g_AllocatedMemorySize[i], (void *)g_AllocatedMemory[i]);
            }
        }
    }
    else
    {
        puts("No memory leaked.");
    }
    // clear the log so the next Init/Done session starts empty
    memset(g_AllocatedMemory, 0, sizeof(g_AllocatedMemory));
    memset(g_AllocatedMemorySize, 0, sizeof(g_AllocatedMemorySize));
    g_AllocCnt = 0;
    g_RevgrindInitialised = FALSE;
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
    int *buf = (int *)malloc(arrSize * sizeof(*buf));

    for (int i = 0; i < arrSize; ++i)
        buf[i] = i;
    printArr(buf, arrSize);

    const int newArrSize = 0;
    int *tmp = NULL;
    tmp = (int *)realloc(buf, newArrSize * sizeof(*tmp));
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
    int *buf = (int *)malloc(arrSize * sizeof(*buf));
    
    assert (buf);
    
    for (int i = 0; i < arrSize; ++i)
        buf[i] = i;
    printArr(buf, arrSize);

    const int newArrSize = 2 * arrSize;
    int *tmp = NULL;
    tmp = (int *)realloc(buf, newArrSize * sizeof(*tmp));
    
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
    buf = (int *)realloc(buf, size * sizeof(*buf));
    
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
    tmp = (int *)realloc(buf, arrSize * sizeof(*tmp));
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
    int *buf = calloc(size, sizeof(*buf));

    printArr(buf, size);

    for (int i = 0; i < size; ++i)
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
    int *buf = calloc(size, sizeof(*buf));

    printArr(buf, size);
    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int testMallocZeroLeak (void)
{
    puts("testMallocZeroLeak");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }
    
    int *buf = malloc(0);

    int *tmp = realloc(buf, 128);
    assert (tmp != NULL);
    buf = tmp;

    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int testMallocZero (void)
{
    puts("testMallocZero");
    if (!MallocDebug_Init())
    {
        puts("Init failed.");
        return 0;
    }
    
    int *buf = malloc(0);

    int *tmp = realloc(buf, 127);
    assert (tmp != NULL);
    buf = tmp;

    free(buf);

    if (!MallocDebug_Done())
        return 0;
    return 1;
}

int main(void)
{
    assert(testMallocZero() == 1);
    assert(testMallocZeroLeak() == 1);
    
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
