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

#define hBEGIN ((BYTE *)pDosHeader)

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
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(hBEGIN + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    return pImportDesc;
}

PIMAGE_IMPORT_DESCRIPTOR findImpDescOfFunc(char *funcName)
{
    for (PIMAGE_IMPORT_DESCRIPTOR pImportDesc = getFirstImpDesc();
         pImportDesc->Characteristics != 0; ++pImportDesc)
    {
        for (PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(VA(pImportDesc->OriginalFirstThunk));
             pOriginalFirstThunk->u1.AddressOfData != 0; ++pOriginalFirstThunk)
        {
            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(VA(pOriginalFirstThunk->u1.AddressOfData));

            if (strncmp("malloc", pImportByName->Name, 6) == 0)
            {
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

    SIZE_T pBytes = count * sizeof(IMAGE_THUNK_DATA);
    DWORD pOldProt = 0;
    return VirtualProtect(t, pBytes, PAGE_READWRITE, &pOldProt);
}

/* look up import descriptor by Name using funcName. Then find it in it's IAT by funcAddr, replace address with pNewFunc  */
BOOL replaceFunc(char *funcName, ULONGLONG funcAddr, ULONGLONG pNewFunc)
{
    // find import descriptor of funcName's .dll
    PIMAGE_IMPORT_DESCRIPTOR funcImpDesc = findImpDescOfFunc(funcName);
    if (funcImpDesc == NULL)
    {
        printf("No Import Descriptor containing function %s found\n", funcName);
        return FALSE;
    }

    // find the func's address in FirstThunk, replace with pNewFunc
    //    - alebo ju viem retrievnut aj podla poradia/inak dajak?
    for (PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(VA(funcImpDesc->FirstThunk));
         pFirstThunk->u1.AddressOfData != 0; ++pFirstThunk)
    {
        if (funcAddr == pFirstThunk->u1.Function)
        {
            if (UnlockFirstThunk(funcImpDesc) == 0)
            {
                DWORD r = GetLastError();
                printf("Unlocking FirstThunk memory for writing failed.\n Error: %d\n", r);
                return FALSE;
            }
            pFirstThunk->u1.Function = pNewFunc;
            return TRUE;
        }
    }
    printf("%s address not found in FirstThunk.\n", funcName);
    return FALSE;
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
        puts("Replacing malloc failed.");
        return FALSE;
    }
    if (!replaceFunc("calloc", (ULONGLONG)g_OrigCalloc, (ULONGLONG)MallocDebug_calloc))
    {
        puts("Replacing calloc failed.");
        return FALSE;
    }
    if (!replaceFunc("realloc", (ULONGLONG)g_OrigRealloc, (ULONGLONG)MallocDebug_realloc))
    {
        puts("Replacing realloc failed.");
        return FALSE;
    }
    if (!replaceFunc("free", (ULONGLONG)g_OrigFree, (ULONGLONG)MallocDebug_free))
    {
        puts("Replacing free failed.");
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
void MallocDebug_Done(void)
{
    if (g_OrigMalloc == NULL)
    {
        puts("Done called but revgrind hasn't been initialised.");
        return;
    }

    // restore original IAT state
    // replace malloc (now Debug_malloc) with gOrigMalloc (malloc), etc.
    replaceFunc("malloc", (ULONGLONG)&malloc, (ULONGLONG)g_OrigMalloc);
    g_OrigMalloc = NULL;
    replaceFunc("calloc", (ULONGLONG)&calloc, (ULONGLONG)g_OrigCalloc);
    g_OrigCalloc = NULL;
    replaceFunc("realloc", (ULONGLONG)&realloc, (ULONGLONG)g_OrigRealloc);
    g_OrigRealloc = NULL;
    replaceFunc("free", (ULONGLONG)&free, (ULONGLONG)g_OrigFree);
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
}

void printFirstThunks(PIMAGE_DOS_HEADER pDosHeader, PIMAGE_IMPORT_DESCRIPTOR pImportDesc)
{
    // PIMAGE_THUNK_DATA arr is 0-terminated
    for (PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(hBEGIN + pImportDesc->FirstThunk);
         pFirstThunk->u1.AddressOfData != 0; ++pFirstThunk)
    {
        // check if address of data is ordinal
        // a teda ci pFirstThunk->u1.Function je typu PIMAGE_THUNK_DATA
        void *pImportByName;
        if (isOrdinalThunk(pFirstThunk))
        {
            pImportByName = (PIMAGE_THUNK_DATA)(hBEGIN + pFirstThunk->u1.Function);
            // pImportByName is now PIMAGE_THUNK_DATA
            printf("Found an ordinal, won't have a name!\n");
            continue;
        }
        else
        {
            pImportByName = (PIMAGE_IMPORT_BY_NAME)(hBEGIN + pFirstThunk->u1.Function);
            // pImportByName is now PIMAGE_IMPORT_BY_NAME
        }
        if ((ULONG_PTR)&malloc == pFirstThunk->u1.Function)
        {

            printf("\t pFirstThunk->u1.Function:\t\t%p\n", (void *)pFirstThunk->u1.Function);
            printf("\t &malloc:\t\t\t\t%p\n", (void *)&malloc);
            printf("\t &MallocDebug_malloc:\t\t\t%p\n", (void *)&MallocDebug_malloc);

            puts("Found malloc.");

            if (UnlockFirstThunk(pImportDesc) == 0)
            {
                DWORD r = GetLastError();
                printf("VirtualProtect failed.\n Error: %d\n", r);
                return;
            }
            puts("Unlocked it's IAT for writing.\n");

            pFirstThunk->u1.Function = (ULONGLONG)&MallocDebug_malloc;

            puts("Replaced malloc with MallocDebug_malloc.\n");

            puts("Calling malloc, should run MallocDebug:");

            int *ptr = malloc(5);
        }
    }
}

// When MSB of AddressOfData is 1, it's an ordinal and
// pFirstThunk->u1.AddressOfData is of type PIMAGE_THUNK_DATA.

BOOL isOrdinalThunk(PIMAGE_THUNK_DATA pThunk)
{
    return IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal) ? TRUE : FALSE;
}

int printOGFirstThunks(PIMAGE_DOS_HEADER pDosHeader, PIMAGE_IMPORT_DESCRIPTOR pImportDesc)
{
    char *libName = (hBEGIN + pImportDesc->Name);
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
    for (PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(hBEGIN + pImportDesc->OriginalFirstThunk);
         pOriginalFirstThunk->u1.AddressOfData != 0; ++pOriginalFirstThunk)
    {
        // check if address of data is ordinal
        // a teda ci pFirstThunk->u1.AddressOfData je typu PIMAGE_THUNK_DATA
        void *pImportByName;
        if (isOrdinalThunk(pOriginalFirstThunk))
        {
            pImportByName = (PIMAGE_THUNK_DATA)(hBEGIN + pOriginalFirstThunk->u1.AddressOfData);
            // pImportByName is now PIMAGE_THUNK_DATA
            printf("Found an ordinal, won't have a name!\n");
            continue;
        }
        else
        {
            pImportByName = (PIMAGE_IMPORT_BY_NAME)(hBEGIN + pOriginalFirstThunk->u1.AddressOfData);
            // pImportByName is now PIMAGE_IMPORT_BY_NAME
        }

        char buf[64] = {0};
        if (strcpy_s(buf, 64, ((PIMAGE_IMPORT_BY_NAME)pImportByName)->Name) == 0)
        {
            printf("\t- %s\n", buf);
            if (strncmp("malloc", buf, 6) == 0)
            {
                // printf("\t# Found malloc!\n");
                printf("\t# malloc's hint: %d\n", ((PIMAGE_IMPORT_BY_NAME)pImportByName)->Hint);
                return 1;
                // pImportByName = (PIMAGE_IMPORT_BY_NAME) (hBEGIN + pFirstThunk->u1.AddressOfData);
                // printFirstThunks(pDosHeader, pImportDesc, pImportByName);
                // IAT of heap dll: program_offset + 303C
            }
            ++cnt;
        }
        else
        {
            printf("Copying to buffer failed.\n");
        }
    }
    printf("Found %d linked functions in %s.\n", cnt, libName);
    return 0;
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

    printf("buf size: %zu\n", _msize(buf));
    for (int i = 0; i < arrSize; ++i)
        buf[i] = i;
    printArr(buf, arrSize);

    const int newArrSize = 0;
    int *oldbuf = buf;
    buf = (int *)realloc(buf, newArrSize * sizeof(int));
    if (buf != NULL)
    {
        MallocDebug_Done();
        return 0;
    }
    MallocDebug_Done();
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

    printf("buf size: %zu\n", _msize(buf));
    for (int i = 0; i < arrSize; ++i)
        buf[i] = i;
    printArr(buf, arrSize);

    const int newArrSize = 2 * arrSize;
    int *oldbuf = buf;
    buf = (int *)realloc(buf, newArrSize * sizeof(int));

    printf("buf newsize: %zu\n", _msize(buf));
    for (int i = arrSize; i < newArrSize; ++i)
        buf[i] = i;
    printArr(buf, newArrSize);

    printf("buf == oldbuf: %d\n", buf == oldbuf);

    free(buf);

    MallocDebug_Done();
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

    for (int i = 0; i < size; ++i)
        buf[i] = i;
    printArr(buf, size);

    free(buf);

    MallocDebug_Done();
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

    printArr(buf, size);

    for (size_t i = 0; i < size; ++i)
        buf[i] = i;
    printArr(buf, size);

    free(buf);
    MallocDebug_Done();
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

    printArr(buf, size);
    MallocDebug_Done();
    return 1;
}

int main(void)
{
    assert(testCallocLeak() == 1);
    assert(testCallocNormal() == 1);
    return EXIT_SUCCESS;
}
