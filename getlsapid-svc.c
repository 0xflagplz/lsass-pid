#include <windows.h>
#include <winsvc.h>  
#include "beacon.h"
#define WINBOOL int

// gotta link these bad boys (api calls) for the BOF linker in the C2
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);

// Query samss for LSA process ID
DWORD GetLsaPidFromService(void) {
    SC_HANDLE              ManagerHandle = NULL, ServiceHandle = NULL;
    SERVICE_STATUS_PROCESS ProcessInfo;
    HANDLE                 Handle = NULL;
    DWORD                  Length, ProcessId = 0;
    BOOL                   Result;

    do {
        // open the Service Control Manager
        // SC_MANAGER_CONNECT - Service Control Manager object specific access types
        //Expands to: 0x0001
        ManagerHandle = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);

        if (!ManagerHandle) {
            BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManager() failed : %ld\n", KERNEL32$GetLastError());
            break;
        }
        // open the samss service
        // for reference:
        //
        // SC_HANDLE OpenServiceW(
        //   [in] SC_HANDLE hSCManager,
        //   [in] LPCWSTR   lpServiceName,
        //   [in] DWORD     dwDesiredAccess
        // );

        ServiceHandle = ADVAPI32$OpenServiceW(
                            ManagerHandle,
                            L"samss",
                            SERVICE_QUERY_STATUS
                        );

        if (!ServiceHandle) {
            BeaconPrintf(CALLBACK_OUTPUT, "OpenService() failed : %ld\n", KERNEL32$GetLastError());
            break;
        }
        // query the service status to get process information and save to memory location of ProcessInfo
        // for reference:
        //
        // BOOL QueryServiceStatusEx(
        //   [in]            SC_HANDLE      hService,
        //   [in]            SC_STATUS_TYPE InfoLevel,
        //   [out, optional] LPBYTE         lpBuffer,  [buffer location to store into (our var ProcessInfo)]
        //   [in]            DWORD          cbBufSize,
        //   [out]           LPDWORD        pcbBytesNeeded
        // );


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
        // since we directed the api QueryServiceStatusEx to use the location &ProcessInfo 
        // we can querythe specific parameter of dwProcessId for the processID
        ProcessId = ProcessInfo.dwProcessId;
    } while(FALSE);


    // Close the service handle
    if (ServiceHandle) {
        ADVAPI32$CloseServiceHandle(ServiceHandle);
    }
    // Close the SC Manager handle
    if (ManagerHandle) {
        ADVAPI32$CloseServiceHandle(ManagerHandle);
    }


    // BeaconPrintf is defined within beacon.h (several CALLBACK_X options for thee console to interpret the output)

    BeaconPrintf(CALLBACK_OUTPUT, "PID: %lu\n", ProcessId);
    
    return ProcessId;

}

// BOF entry function
int go() {
    GetLsaPidFromService();
    return;
}