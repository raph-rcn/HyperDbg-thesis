/**
 * @file Common.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Routines for common tasks in debugger
 * @details
 * @version 0.2
 * @date 2023-01-22
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

#define SYSTEM_PROCESS_INFORMATION_CLASS 5
#define INITIAL_PROCESS_LIST_QUERY_SIZE 0x10000
#define MAX_PROCESS_LIST_QUERY_SIZE     0x400000

typedef struct _HYPERDBG_SYSTEM_PROCESS_INFORMATION
{
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   WorkingSetPrivateSize;
    ULONG           HardFaultCount;
    ULONG           NumberOfThreadsHighWatermark;
    ULONGLONG       CycleTime;
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    KPRIORITY       BasePriority;
    HANDLE          UniqueProcessId;
    PVOID           Reserved2;
} HYPERDBG_SYSTEM_PROCESS_INFORMATION, *PHYPERDBG_SYSTEM_PROCESS_INFORMATION;

NTSYSAPI NTSTATUS NTAPI
ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);

/**
 * @brief Checks whether the process with ProcId exists or not
 *
 * @details this function should NOT be called from vmx-root mode
 *
 * @param UINT32 ProcId
 * @return BOOLEAN Returns true if the process
 * exists and false if it the process doesn't exist
 */
BOOLEAN
CommonIsProcessExist(UINT32 ProcId)
{
    PEPROCESS TargetEprocess;

    if (PsLookupProcessByProcessId((HANDLE)ProcId, &TargetEprocess) != STATUS_SUCCESS)
    {
        //
        // There was an error, probably the process id was not found
        //
        return FALSE;
    }
    else
    {
        ObDereferenceObject(TargetEprocess);

        return TRUE;
    }
}

/**
 * @brief Finds a currently running process by PsGetProcessImageFileName()
 *
 * @details this function should NOT be called from vmx-root mode
 *
 * @param ProcessNameBuffer EPROCESS ImageFileName-compatible basename
 * @param LengthOfProcessName Length in bytes, excluding NUL
 * @param ProcessId Receives the matching process id
 *
 * @return BOOLEAN Returns true if a matching process exists
 */
BOOLEAN
CommonFindProcessIdByImageFileName(PVOID ProcessNameBuffer, UINT32 LengthOfProcessName, PUINT32 ProcessId)
{
    NTSTATUS                               Status;
    ULONG                                  BufferSize = INITIAL_PROCESS_LIST_QUERY_SIZE;
    ULONG                                  ReturnLength;
    PVOID                                  Buffer = NULL;
    PHYPERDBG_SYSTEM_PROCESS_INFORMATION   ProcessInfo;
    PEPROCESS                              Eprocess = NULL;
    PCHAR                                  ImageFileName;

    if (ProcessNameBuffer == NULL || ProcessId == NULL || LengthOfProcessName == 0)
    {
        return FALSE;
    }

    if (LengthOfProcessName >= 16)
    {
        LengthOfProcessName = 15;
    }

    for (;;)
    {
        Buffer = PlatformMemAllocateZeroedNonPagedPool(BufferSize);
        if (Buffer == NULL)
        {
            return FALSE;
        }

        ReturnLength = 0;
        Status       = ZwQuerySystemInformation(SYSTEM_PROCESS_INFORMATION_CLASS,
                                                Buffer,
                                                BufferSize,
                                                &ReturnLength);
        if (Status == STATUS_INFO_LENGTH_MISMATCH)
        {
            PlatformMemFreePool(Buffer);
            Buffer = NULL;

            if (ReturnLength > BufferSize)
            {
                BufferSize = ReturnLength + PAGE_SIZE;
            }
            else
            {
                BufferSize = BufferSize * 2;
            }

            if (BufferSize > MAX_PROCESS_LIST_QUERY_SIZE)
            {
                return FALSE;
            }

            continue;
        }

        if (!NT_SUCCESS(Status))
        {
            PlatformMemFreePool(Buffer);
            return FALSE;
        }

        break;
    }

    ProcessInfo = (PHYPERDBG_SYSTEM_PROCESS_INFORMATION)Buffer;
    for (;;)
    {
        if (ProcessInfo->UniqueProcessId != NULL &&
            NT_SUCCESS(PsLookupProcessByProcessId(ProcessInfo->UniqueProcessId, &Eprocess)))
        {
            ImageFileName = CommonGetProcessNameFromProcessControlBlock(Eprocess);
            if (ImageFileName != NULL &&
                _strnicmp((const char *)ImageFileName,
                          (const char *)ProcessNameBuffer,
                          LengthOfProcessName) == 0 &&
                (LengthOfProcessName >= 15 || ImageFileName[LengthOfProcessName] == '\0'))
            {
                *ProcessId = HANDLE_TO_UINT32(ProcessInfo->UniqueProcessId);
                ObDereferenceObject(Eprocess);
                PlatformMemFreePool(Buffer);
                return TRUE;
            }

            ObDereferenceObject(Eprocess);
        }

        if (ProcessInfo->NextEntryOffset == 0)
        {
            break;
        }

        ProcessInfo = (PHYPERDBG_SYSTEM_PROCESS_INFORMATION)((UINT64)ProcessInfo + ProcessInfo->NextEntryOffset);
    }

    PlatformMemFreePool(Buffer);
    return FALSE;
}

/**
 * @brief Get handle from Process Id
 * @param Handle
 * @param ProcessId
 *
 * @return NTSTATUS
 */
_Use_decl_annotations_
NTSTATUS
CommonGetHandleFromProcess(UINT32 ProcessId, PHANDLE Handle)
{
    NTSTATUS Status;
    Status                    = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjAttr = {0};
    CLIENT_ID         Cid     = {0};
    InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);

    Cid.UniqueProcess = (HANDLE)ProcessId;
    Cid.UniqueThread  = (HANDLE)0;

    Status = ZwOpenProcess(Handle, PROCESS_ALL_ACCESS, &ObjAttr, &Cid);

    return Status;
}

/**
 * @brief Get process name by eprocess
 *
 * @param Eprocess Process eprocess
 * @return PCHAR Returns a pointer to the process name
 */
PCHAR
CommonGetProcessNameFromProcessControlBlock(PEPROCESS Eprocess)
{
    PCHAR Result = 0;

    //
    // We can't use PsLookupProcessByProcessId as in pageable and not
    // work on vmx-root
    //
    Result = (CHAR *)PsGetProcessImageFileName(Eprocess);

    return Result;
}

/**
 * @brief The undocumented way of NtOpenProcess
 * @param ProcessHandle
 * @param DesiredAccess
 * @param ProcessId
 * @param AccessMode
 *
 * @return NTSTATUS
 */
NTSTATUS
CommonUndocumentedNtOpenProcess(
    PHANDLE         ProcessHandle,
    ACCESS_MASK     DesiredAccess,
    HANDLE          ProcessId,
    KPROCESSOR_MODE AccessMode)
{
    NTSTATUS     Status = STATUS_SUCCESS;
    ACCESS_STATE AccessState;
    CHAR         AuxData[0x200] = {0};
    PEPROCESS    ProcessObject  = NULL;
    HANDLE       ProcHandle     = NULL;

    Status = SeCreateAccessState(
        &AccessState,
        AuxData,
        DesiredAccess,
        (PGENERIC_MAPPING)((PCHAR)*PsProcessType + 52));

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    AccessState.PreviouslyGrantedAccess |= AccessState.RemainingDesiredAccess;
    AccessState.RemainingDesiredAccess = 0;

    Status = PsLookupProcessByProcessId(ProcessId, &ProcessObject);

    if (!NT_SUCCESS(Status))
    {
        SeDeleteAccessState(&AccessState);
        return Status;
    }
    Status = ObOpenObjectByPointer(
        ProcessObject,
        0,
        &AccessState,
        0,
        *PsProcessType,
        AccessMode,
        &ProcHandle);

    SeDeleteAccessState(&AccessState);

    ObDereferenceObject(ProcessObject);

    if (NT_SUCCESS(Status))
        *ProcessHandle = ProcHandle;

    return Status;
}

/**
 * @brief Kill a user-mode process with different methods
 * @param ProcessId
 * @param KillingMethod
 *
 * @return BOOLEAN
 */
_Use_decl_annotations_
BOOLEAN
CommonKillProcess(UINT32 ProcessId, PROCESS_KILL_METHODS KillingMethod)
{
    NTSTATUS  Status        = STATUS_SUCCESS;
    HANDLE    ProcessHandle = NULL;
    PEPROCESS Process       = NULL;

    if (ProcessId == NULL_ZERO)
    {
        return FALSE;
    }

    switch (KillingMethod)
    {
    case PROCESS_KILL_METHOD_1:

        Status = CommonGetHandleFromProcess(ProcessId, &ProcessHandle);

        if (!NT_SUCCESS(Status) || ProcessHandle == NULL)
        {
            return FALSE;
        }

        //
        // Call ZwTerminateProcess with NULL handle
        //
        Status = ZwTerminateProcess(ProcessHandle, 0);

        if (!NT_SUCCESS(Status))
        {
            return FALSE;
        }

        break;

    case PROCESS_KILL_METHOD_2:

        CommonUndocumentedNtOpenProcess(
            &ProcessHandle,
            PROCESS_ALL_ACCESS,
            (HANDLE)ProcessId,
            KernelMode);

        if (ProcessHandle == NULL)
        {
            return FALSE;
        }

        //
        // Call ZwTerminateProcess with NULL handle
        //
        Status = ZwTerminateProcess(ProcessHandle, 0);

        if (!NT_SUCCESS(Status))
        {
            return FALSE;
        }

        break;

    case PROCESS_KILL_METHOD_3:

        //
        // Get the base address of process's executable image and unmap it
        //
        Status = MmUnmapViewOfSection(Process, PsGetProcessSectionBaseAddress(Process));

        //
        // Dereference the target process
        //
        ObDereferenceObject(Process);

        break;

    default:

        //
        // Unknown killing method
        //
        return FALSE;
        break;
    }

    //
    // If we reached here, it means the functionality of
    // the above codes was successful
    //
    return TRUE;
}

/**
 * @brief Validate core number
 * @param CoreNumber
 *
 * @return BOOLEAN
 */
_Use_decl_annotations_
BOOLEAN
CommonValidateCoreNumber(UINT32 CoreNumber)
{
    ULONG ProcessorsCount;

    ProcessorsCount = KeQueryActiveProcessorCount(0);

    if (CoreNumber >= ProcessorsCount)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}
