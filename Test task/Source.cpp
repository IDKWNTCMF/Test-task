#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define FILENAME "C:\\temp\\file.txt"

#include <windows.h>
#endif

#ifdef __linux__
#define FILENAME "/mnt/c/temp/file.txt"

#include <dlfcn.h>
#include <unistd.h>
#endif


void CWE114_Process_Control__w32_char_file_01_bad()
{
    char* data;


    char buff[100] = "";

#ifdef _WIN32
    HANDLE hFile;
    DWORD lpNumberOfBytesRead;

    hFile = CreateFileA(
        FILENAME,
        GENERIC_READ,
        0, NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        MessageBox(NULL, TEXT("Cannot open file"), TEXT("Warning"), MB_OK);
        return;
    }
    do
    {
        ReadFile(
            hFile,
            buff, sizeof(buff), &lpNumberOfBytesRead, NULL);
        if (lpNumberOfBytesRead == 0)
            break;

    } while (lpNumberOfBytesRead != 0);

    CloseHandle(hFile);

    data = buff;

    {
        HMODULE hModule;
        /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
         * replace his own file with the intended library */
        hModule = LoadLibraryA(data);
        if (hModule != NULL)
        {
            FreeLibrary(hModule);
            printf("Library loaded and freed successfully\n");
        }
        else
        {
            printf("Unable to load library\n");
        }
    }
#endif

#ifdef __linux__
    int fd = open(FILENAME, O_RDONLY);
    if (fd == -1)
    {
        printf("Warning: Cannot open file!\n");
        return;
    }

    uint32_t lpNumberOfBytesRead;
    do
    {
        lpNumberOfBytesRead = read(fd, buff, sizeof(buff));
        if (lpNumberOfBytesRead == 0)
            break;
    } while (lpNumberOfBytesRead != 0);

    close(fd);

    data = buff;

    {
        void *handle;
        /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
         * replace his own file with the intended library */
        handle = dlopen(data, RTLD_LAZY);
        if (handle) {
            dlclose(handle);
            printf("Library loaded and freed successfully\n");
        } else {
            printf("Unable to load library\n");
        }
    }
#endif
}



/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char* data;
    char dataBuffer[100] = "";
    data = dataBuffer;

#ifdef _WIN32
    /* FIX: Specify the full pathname for the library */
    strcpy(data, "C:\\Windows\\System32\\winsrv.dll");
    {
        HMODULE hModule;
        /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
         * replace his own file with the intended library */
        hModule = LoadLibraryA(data);
        if (hModule != NULL)
        {
            FreeLibrary(hModule);
            printf("Library loaded and freed successfully \n");
        }
        else
        {
            printf("Unable to load library\n");
        }
    }
#endif

#ifdef __linux__
    /* FIX: Specify the full pathname for the library */
    strcpy(data, "/mnt/c/libopt.so");
    {
        void *handle;
        /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
         * replace his own file with the intended library */
        handle = dlopen(data, RTLD_LAZY);
        if (handle) {
            dlclose(handle);
            printf("Library loaded and freed successfully\n");
        } else {
            printf("Unable to load library\n");
        }
    }
#endif
}

void CWE114_Process_Control__w32_char_file_01_good()
{
    goodG2B();
}



/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */



int main(int argc, char* argv[])
{
    /* seed randomness */
    srand((unsigned)time(NULL));
    printf("Calling good()... \n");
    CWE114_Process_Control__w32_char_file_01_good();
    printf("Finished good() \n");

    printf("Calling bad()...\n");
    CWE114_Process_Control__w32_char_file_01_bad();
    printf("Finished bad() \n");
    return 0;
}
