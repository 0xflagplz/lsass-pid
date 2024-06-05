#include <windows.h>
#include <winsvc.h>  // Make sure to include this before using WINBOOL
#include "beacon.h"
#define WINBOOL int

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
//
// Query samss for LSA process ID.
//
DWORD GetLsaPidFromService(void) {
    SC_HANDLE              ManagerHandle = NULL, ServiceHandle = NULL;
    SERVICE_STATUS_PROCESS ProcessInfo;
    HANDLE                 Handle = NULL;
    DWORD                  Length, ProcessId = 0;
    BOOL                   Result;

    do {
        ManagerHandle = ADVAPI32$OpenSCManagerW(
                            NULL,
                            NULL,
                            SC_MANAGER_CONNECT
                        );

        if (!ManagerHandle) {
            BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManager() failed : %ld\n", KERNEL32$GetLastError());
            break;
        }

        ServiceHandle = ADVAPI32$OpenServiceW(
                            ManagerHandle,
                            L"samss",
                            SERVICE_QUERY_STATUS
                        );

        if (!ServiceHandle) {
            BeaconPrintf(CALLBACK_OUTPUT, "OpenService() failed : %ld\n", KERNEL32$GetLastError());
            break;
        }

        Result = ADVAPI32$QueryServiceStatusEx(
                    ServiceHandle,
                    SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ProcessInfo,
                    sizeof(ProcessInfo),
                    &Length
                );

        if (!Result) {
            BeaconPrintf(CALLBACK_OUTPUT, "QueryServiceStatusEx() failed : %ld\n", KERNEL32$GetLastError());
            break;
        }

        ProcessId = ProcessInfo.dwProcessId;
    } while(FALSE);

    if (ServiceHandle) {
        ADVAPI32$CloseServiceHandle(ServiceHandle);
    }

    if (ManagerHandle) {
        ADVAPI32$CloseServiceHandle(ManagerHandle);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "PID: %lu\n", ProcessId);
    
    return ProcessId;

}

// BOF entry function
int go() {
    GetLsaPidFromService();
    return;
}