/*++

Original Author: Copyright (c) 1999-2002  Microsoft Corporation
Modified by: SafeBreach Labs (August 2020)

Module Name:

    scanner.c

Abstract:

    This is the main module of the AFW_Mitigation filter.

    More details on SafeBreach Labs' Spooler Repository on GitHub.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "scanner.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//
//  Structure that contains all the global data structures
//  used throughout the scanner.
//

SCANNER_DATA ScannerData;

//
//  Function prototypes
//

NTSTATUS
ScannerpScanFile(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN SafeToOpen,
    _In_ BOOLEAN IsUserSystem,
    _In_ BOOLEAN IsFileInTasksDir,
    _In_ BOOLEAN IsFileInSpoolerDir
);

NTSTATUS ScannerpIsUserSystem(
    _Out_ BOOLEAN* IsSystem
);

NTSTATUS
ScannerpGetProcessImageName(
    _In_ PEPROCESS eProcess,
    _Out_ PUNICODE_STRING* ProcessImageName
);

BOOLEAN
ScannerpIsProcessSvchost(
    _In_ PEPROCESS eProcess
);

BOOLEAN
ScannerpIsProcessSpooler(
    _In_ PEPROCESS eProcess
);

BOOLEAN
ScannerpIsFileInGivenDirectory(
    _In_ PUNICODE_STRING FilePath,
    _In_ PUNICODE_STRING DirectoryPath
);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(PAGE, ScannerInstanceSetup) 
    #pragma alloc_text(PAGE, ScannerpIsUserSystem)
    #pragma alloc_text(PAGE, ScannerpIsFileInGivenDirectory)
    #pragma alloc_text(PAGE, ScannerpIsProcessSvchost)
    #pragma alloc_text(PAGE, ScannerpIsProcessSpooler)
    #pragma alloc_text(PAGE, ScannerpGetProcessImageName)
    #pragma alloc_text(PAGE, ScannerPostCreate)
    #pragma alloc_text(PAGE, ScannerPreCleanup)
    #pragma alloc_text(PAGE, ScannerPreSetInformation)
#endif


//
//  Constant FLT_REGISTRATION structure for our filter.  This
//  initializes the callback routines our filter wants to register
//  for.  This is only used to register with the filter manager
//

const FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      NULL,
      ScannerPostCreate},

      { IRP_MJ_SET_INFORMATION,
      0,
      ScannerPreSetInformation,
      NULL},

    { IRP_MJ_CLEANUP,
      0,
      ScannerPreCleanup,
      NULL },

    { IRP_MJ_OPERATION_END}
};


const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_STREAMHANDLE_CONTEXT,
      0,
      NULL,
      sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
      'chBS' },

    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    ContextRegistration,                //  Context Registration.
    Callbacks,                          //  Operation callbacks
    ScannerUnload,                      //  FilterUnload
    ScannerInstanceSetup,               //  InstanceSetup
    ScannerQueryTeardown,               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};

////////////////////////////////////////////////////////////////////////////
//
//    Filter initialization and unload routines.
//
////////////////////////////////////////////////////////////////////////////

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for the Filter driver.  This
    registers the Filter with the filter manager and initializes all
    its global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.
--*/
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    //
    //  Default to NonPagedPoolNx for non paged pool allocations where supported.
    //
    
    ExInitializeDriverRuntime( DrvRtPoolNxOptIn );

    //
    //  Register with filter manager.
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &ScannerData.Filter );


    if (!NT_SUCCESS( status )) {

        return status;
    }

        if (NT_SUCCESS( status )) {

            //
            //  Start filtering I/O.
            //

            status = FltStartFiltering( ScannerData.Filter );

            if (NT_SUCCESS( status )) {

                return STATUS_SUCCESS;
            }

    }

    FltUnregisterFilter( ScannerData.Filter );
    
    return status;
}

NTSTATUS
ScannerUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for the Filter driver.  This unregisters the
    Filter with the filter manager and frees any allocated global data
    structures.

Arguments:

    None.

Return Value:

    Returns the final status of the deallocation routines.

--*/
{
    UNREFERENCED_PARAMETER( Flags );


    //
    //  Unregister the filter
    //

    FltUnregisterFilter( ScannerData.Filter );

    return STATUS_SUCCESS;
}


NTSTATUS
ScannerInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called by the filter manager when a new instance is created.
    We specified in the registry that we only want for manual attachments,
    so that is all we should receive here.

Arguments:

    FltObjects - Describes the instance and volume which we are being asked to
        setup.

    Flags - Flags describing the type of attachment this is.

    VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
        will attach.

    VolumeFileSystemType - The file system formatted on this volume.

Return Value:

  STATUS_SUCCESS            - we wish to attach to the volume
  STATUS_FLT_DO_NOT_ATTACH  - no, thank you

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    FLT_ASSERT( FltObjects->Filter == ScannerData.Filter );

    //
    //  Don't attach to network volumes.
    //

    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

       return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
ScannerQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is the instance detach routine for the filter. This
    routine is called by filter manager when a user initiates a manual instance
    detach. This is a 'query' routine: if the filter does not want to support
    manual detach, it can return a failure status

Arguments:

    FltObjects - Describes the instance and volume for which we are receiving
        this query teardown request.

    Flags - Unused

Return Value:

    STATUS_SUCCESS - we allow instance detach to happen

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    return STATUS_SUCCESS;
}



NTSTATUS
ScannerpGetProcessImageName(
    _In_ PEPROCESS eProcess,
    _Out_ PUNICODE_STRING* ProcessImageName
)
/*++

Routine Description:

    Retrieve the image name of the process which the IRP initiated from
Arguments

    eProcess - Pointer to the current EPROCESS struct.
    ProcessImageName - Pointer to a UNICODE_STRING buffer which is allocated within the function. 
        This buffer needs to be freed outside of the function.

Return Value
    STATUS_SUCCESS - Image name retreived successfully.
    STATUS_INVALID_PARAMETER_1 - Pointer to EPROCESS is invalid.
    STATUS_INSUFFICIENT_RESOURCES - Allocation of UNICODE_STRING buffer was failed.
    
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG returnedLength;
    HANDLE hProcess = NULL;
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
    

    PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

    if (NULL == eProcess)
    {
        return STATUS_INVALID_PARAMETER_1;
    }


    /*
    status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, UserMode, &hProcess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
        return status;
    } */


    if (NULL == ZwQueryInformationProcess)
    {
        ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

        if (NULL == ZwQueryInformationProcess)
        {
            DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
            status = STATUS_UNSUCCESSFUL;
            goto ScannerpGetProcessImageNameCleanup;
        }
    }

    /* Query the actual size of the process path */
    status = ZwQueryInformationProcess(ZwCurrentProcess(),
        ProcessImageFileName,
        NULL, // buffer
        0,    // buffer size
        &returnedLength);

    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        DbgPrint("ZwQueryInformationProcess status = %x\n", status);
        goto ScannerpGetProcessImageNameCleanup;
    }


 
    *ProcessImageName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, 'corP');

    // ProcessImageName must be allocated before calling this function!
    if (NULL == *ProcessImageName)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ScannerpGetProcessImageNameCleanup;
    }

    /* Retrieve the process path from the handle to the process */
    status = ZwQueryInformationProcess(ZwCurrentProcess(),
        ProcessImageFileName,
        *ProcessImageName,
        returnedLength,
        &returnedLength);

    if (0 == returnedLength) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    
ScannerpGetProcessImageNameCleanup:
    ZwClose(hProcess);

    return status;
}

BOOLEAN
ScannerpIsProcessSvchost(
    _In_ PEPROCESS eProcess
)
/*++

Routine Description:

    Checks if the current process is System32\svchost.exe

Arguments

    eProcess - Pointer to EPROCESS.

Return Value

    TRUE - Process is System32\svchost.exe
    FALSE - No
--*/
{
    NTSTATUS status;
    PUNICODE_STRING pProcessImageName = NULL;
    BOOLEAN bIsProcessSvchost;
    // TODO: Validate HarddiskVolume is actually the System drive letter
    UNICODE_STRING SvchostPattern = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume*\\Windows\\System32\\svchost.exe");

    bIsProcessSvchost = FALSE;


    status = ScannerpGetProcessImageName(eProcess, &pProcessImageName);
    if (!NT_SUCCESS(status) || NULL == pProcessImageName || NULL == pProcessImageName->Buffer) {
        DbgPrint("ScannerpGetProcessImageName failed: %08x\n", status);
        return FALSE;
    }

    bIsProcessSvchost = FsRtlIsNameInExpression(&SvchostPattern, pProcessImageName, FALSE, NULL);
    if (NULL != pProcessImageName) {
        ExFreePoolWithTag(pProcessImageName, 'corP');
    }
    return bIsProcessSvchost;
}

BOOLEAN
ScannerpIsProcessSpooler(
    _In_ PEPROCESS eProcess
)
/*++

Routine Description:

    Checks if the current process is System32\spoolsv.exe

Arguments

    eProcess - Pointer to EPROCESS.

Return Value

    TRUE - Process is System32\spoolsv.exe
--*/
{
    NTSTATUS status;
    PUNICODE_STRING pProcessImageName = NULL;
    BOOLEAN bIsProcessSpooler;
    // TODO: Validate HarddiskVolume is actually the System drive letter
    UNICODE_STRING SpoolerPattern = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume*\\Windows\\System32\\spoolsv.exe");

    bIsProcessSpooler = FALSE;

    status = ScannerpGetProcessImageName(eProcess, &pProcessImageName);
    if (!NT_SUCCESS(status) || NULL == pProcessImageName || NULL == pProcessImageName->Buffer) {
        return FALSE;
    }

    bIsProcessSpooler = FsRtlIsNameInExpression(&SpoolerPattern, pProcessImageName, FALSE, NULL);
    if (NULL != pProcessImageName) {
        ExFreePoolWithTag(pProcessImageName, 'corP');
    }
    return bIsProcessSpooler;
}

BOOLEAN
ScannerpIsFileInGivenDirectory(
    _In_ PUNICODE_STRING FilePath,
    _In_ PUNICODE_STRING DirectoryPath
)
/*++

Routine Description:

    Checks if this file path is located within the specified folder

Arguments

    FilePath - Pointer to the file path
    DirectoryPath - Pointer to the Directory path

Return Value

    TRUE - File path is located within the specified folder
    FALSE - No
--*/
{
    if (NULL == FilePath || 0 == FilePath->Length) {
        return FALSE;
    }

    if (RtlPrefixUnicodeString(DirectoryPath, FilePath, TRUE)) {
        return TRUE;
    }
   
    return FALSE;
}


FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

    Post create callback.  
Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - The operation context passed fron the pre-create
        callback.

    Flags - Flags to say why we are getting this post-operation callback.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
                                     access to this file, hence undo the open

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    ACCESS_MASK GrantedAccess;
    BOOLEAN Granted;
    PSECURITY_DESCRIPTOR pFileSecurityDescriptor = NULL;
    ULONG LengthNeeded = 0;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    status = FltQuerySecurityObject(FltObjects->Instance,
        FltObjects->FileObject,
        DACL_SECURITY_INFORMATION,
        NULL,
        0,
        &LengthNeeded);

    pFileSecurityDescriptor = FltAllocatePoolAlignedWithTag(FltObjects->Instance,
        NonPagedPool,
        (SIZE_T)LengthNeeded,
        'sdsd');
        
    if (NULL == pFileSecurityDescriptor) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltQuerySecurityObject(FltObjects->Instance,
        FltObjects->FileObject,
        DACL_SECURITY_INFORMATION,
        pFileSecurityDescriptor,
        LengthNeeded,
        NULL);
    
    if (!NT_SUCCESS(status)) {
        FltFreePoolAlignedWithTag(FltObjects->Instance, pFileSecurityDescriptor, 'sdsd');
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    SeCaptureSubjectContext(&SubjectContext);

    // Validate if the user has write permissions to the file
    Granted = SeAccessCheck(pFileSecurityDescriptor,
        &SubjectContext,
        TRUE,
        FILE_WRITE_DATA,
        0,
        NULL,
        IoGetFileObjectGenericMapping(),
        Data->RequestorMode,
        &GrantedAccess,
        &status);

    FltFreePoolAlignedWithTag(FltObjects->Instance, pFileSecurityDescriptor, 'sdsd');

    SeReleaseSubjectContext(&SubjectContext);
    
    // Allocate Stream Handle context, and save the WriteAccess for future processing (IRP_MJ_SET_INFORMATION).
    status = FltAllocateContext(FltObjects->Filter,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
        NonPagedPool,
        &context);

    if (NT_SUCCESS(status)) {
        context->HasWriteAccess = Granted;

        (VOID)FltSetStreamHandleContext(FltObjects->Instance,
            FltObjects->FileObject,
            FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
            context,
            NULL);
    }

    if (context != NULL) {
        FltReleaseContext(context);
    }
    
    return FLT_POSTOP_FINISHED_PROCESSING;

}


FLT_PREOP_CALLBACK_STATUS
ScannerPreCleanup (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre cleanup callback.

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this pre-cleanup callback to the post-cleanup callback.

Return Value:

    FLT_PREOP_SUCCESS_NO_CALLBACK or FLT_PREOP_COMPLETE.

--*/
{
	NTSTATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    NTSTATUS status;
	BOOLEAN safeToOpen;
	FILE_DISPOSITION_INFORMATION  fdi;
	UNICODE_STRING SpoolerDirPath = RTL_CONSTANT_STRING(L"\\Windows\\System32\\SPOOL\\Printers");
	UNICODE_STRING TasksDirPath = RTL_CONSTANT_STRING(L"\\Windows\\System32\\tasks");
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	BOOLEAN IsFileInSpoolerDir = FALSE;
	BOOLEAN IsFileInTasksDir = FALSE;
	BOOLEAN IsUserSystem = FALSE;
	BOOLEAN IsProcessSvchost = FALSE;
	BOOLEAN IsProcessSpooler = FALSE;
	BOOLEAN scanFile = FALSE;

    UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext = NULL );
  

    PAGED_CODE();
   
    // If file doesn't have WriteAccess it's not relevant for us, return.
	if (!FltObjects->FileObject->WriteAccess) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
    
    
    // Extract the filename and parse it
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED |
        FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (!NT_SUCCESS(status)) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);


	(VOID)ScannerpIsUserSystem(&IsUserSystem);
	IsFileInSpoolerDir = ScannerpIsFileInGivenDirectory(&nameInfo->ParentDir, &SpoolerDirPath);
	IsFileInTasksDir = ScannerpIsFileInGivenDirectory(&nameInfo->ParentDir, &TasksDirPath);
	IsProcessSvchost = ScannerpIsProcessSvchost(IoThreadToProcess(Data->Thread));
	IsProcessSpooler = ScannerpIsProcessSpooler(IoThreadToProcess(Data->Thread));

    // Scan the file if the current user is not SYSTEM
	if (!IsUserSystem) {
        // Scenario 1 (CVE-2020-1048): Scan the file if the file is in SPOOL dir and the process is not spoolsv.exe
		if (IsFileInSpoolerDir && !IsProcessSpooler) {
			scanFile = TRUE;
		}
        // Scenario 2a (CVE-2019-1069): Scan the file if it's in Tasks Dir.
		else if (IsFileInTasksDir) {
			scanFile = TRUE;
		}
	}


    // If there's no need to scan the file, just return and continue.
	if (!scanFile) {
		FltReleaseFileNameInformation(nameInfo);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

    // Scan the file
	(VOID)ScannerpScanFile(Data,
		FltObjects->Instance,
		FltObjects->FileObject,
		&safeToOpen,
        IsUserSystem,
        IsFileInTasksDir,
        IsFileInSpoolerDir);

    // If it's not safe, return ACCESS DENIED and Delete the file.
	if (!safeToOpen) {

		if (NT_SUCCESS(status)) {
				DbgPrint("!!! scanner.sys -- malicious attempt of a file creation was detected during precleanup, deleting file %ws!!!\n", nameInfo->Name.Buffer);

				fdi.DeleteFile = TRUE;
				FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &fdi, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);

				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;

				returnStatus = FLT_PREOP_COMPLETE;
		}
	}
	FltReleaseFileNameInformation(nameInfo);


    return returnStatus;
}


FLT_PREOP_CALLBACK_STATUS
ScannerPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

    Pre Set Information callback. 

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this pre-write callback to the post-write callback.

Return Value:

    Always FLT_PREOP_SUCCESS_NO_CALLBACK or FLT_PREOP_COMPLETE.

--*/
{
    PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;
    FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PFILE_LINK_INFORMATION LinkInfo =
        Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION TargetFileInfo = NULL;
    PFLT_FILE_NAME_INFORMATION LinkFileInfo = NULL;
   
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext = NULL);

    
    PAGED_CODE();

    // Ignore the operation if it's not Link creation.
    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileLinkInformation) {
        return returnStatus;
    }

    // Retrieve and parse the file name and the target file name of the link.
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED |
        FLT_FILE_NAME_QUERY_DEFAULT,
        &TargetFileInfo);

    Status = FltGetDestinationFileNameInformation(FltObjects->Instance,
        FltObjects->FileObject,
        LinkInfo->RootDirectory,
        LinkInfo->FileName,
        LinkInfo->FileNameLength,
        FLT_FILE_NAME_OPENED |
        FLT_FILE_NAME_QUERY_DEFAULT |
        FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER,
        &LinkFileInfo);

    Status = FltParseFileNameInformation(LinkFileInfo);
    Status = FltParseFileNameInformation(TargetFileInfo);

    // Retrieve the Context (which contains data from the PostCreate callback)
    Status = FltGetStreamHandleContext(FltObjects->Instance,
        FltObjects->FileObject,
        &context);

    if (context != NULL) {
        // If the user doesn't have write access to the target of the hardlink -- Block it
        if (!context->HasWriteAccess) {
            DbgPrint("Hardlink Creation from %ws to %ws was denied, ACCESS DENIED!\n", LinkFileInfo->Name.Buffer, TargetFileInfo->Name.Buffer);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            returnStatus = FLT_PREOP_COMPLETE;
        }

        FltReleaseContext(context);
    }

    if (LinkFileInfo != NULL) {

        FltReleaseFileNameInformation(LinkFileInfo);
    }

    if (TargetFileInfo != NULL) {

        FltReleaseFileNameInformation(TargetFileInfo);
    }
    return returnStatus;
}



//////////////////////////////////////////////////////////////////////////
//  Local support routines.
//
/////////////////////////////////////////////////////////////////////////

NTSTATUS
ScannerpScanFile(
	_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN SafeToOpen,
    _In_ BOOLEAN IsUserSystem,
    _In_ BOOLEAN IsFileInTasksDir,
    _In_ BOOLEAN IsFileInSpoolerDir
)
/*++

Routine Description:

    Note that if the scan fails, we set SafeToOpen to TRUE.

Arguments:

    Instance - Handle to the filter instance for the scanner on this volume.

    FileObject - File to be scanned.

    SafeToOpen - Set to FALSE if the file is scanned successfully and it contains
                 foul language.

Return Value:

    The status of the operation, hopefully STATUS_SUCCESS.  The common failure
    status will probably be STATUS_INSUFFICIENT_RESOURCES.

--*/

{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR buffer = NULL;
    ULONG bytesRead;
    FLT_VOLUME_PROPERTIES volumeProps;
    LARGE_INTEGER offset;
    ULONG length;
    PFLT_VOLUME volume = NULL;

    try {


        //
        //  Obtain the volume object .
        //
        status = FltGetVolumeFromInstance(Instance, &volume);

        if (!NT_SUCCESS(status)) {

            leave;
        }

        //
        //  Determine sector size. Noncached I/O can only be done at sector size offsets, and in lengths which are
        //  multiples of sector size. A more efficient way is to make this call once and remember the sector size in the
        //  instance setup routine and setup an instance context where we can cache it.
        //

        status = FltGetVolumeProperties(volume,
            &volumeProps,
            sizeof(volumeProps),
            &length);
        //
        //  STATUS_BUFFER_OVERFLOW can be returned - however we only need the properties, not the names
        //  hence we only check for error status.
        //

        if (NT_ERROR(status)) {

            leave;
        }

        length = max(1024, volumeProps.SectorSize);

		buffer = FltAllocatePoolAlignedWithTag(Instance,
			NonPagedPool,
			length,
			'nacS');

        if (NULL == buffer) {

            status = STATUS_INSUFFICIENT_RESOURCES;
            leave;
        }
		status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			&nameInfo);

		if (!NT_SUCCESS(status)) {

			return FLT_POSTOP_FINISHED_PROCESSING;
		}

        FltParseFileNameInformation(nameInfo);

        offset.QuadPart = bytesRead = 0;
        status = FltReadFile(Instance,
            FileObject,
            &offset,
            length,
            buffer,
            FLTFL_IO_OPERATION_NON_CACHED |
            FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            &bytesRead,
            NULL,
            NULL);

        if (NT_SUCCESS(status)) {
            DbgPrint("SYSTEM: %d, SPOOLER: %d, TASKS: %d\n", IsUserSystem, IsFileInSpoolerDir, IsFileInTasksDir);
            if (IsFileInTasksDir == TRUE && IsUserSystem == FALSE) {
                // Handling only Unicode for PoC purposes
                if (buffer[2] != '<' || buffer[4] != '?' || buffer[6] != 'x' || buffer[8] != 'm') {
                    DbgPrint("scanner.sys -- Task Scheduler Exploitation Prevented\n");
                    *SafeToOpen = FALSE;
                }
            }
            // Handling CVE-2020-1048 for PoC Purposes
            else if (IsFileInSpoolerDir == TRUE && IsUserSystem == FALSE) {
                *SafeToOpen = FALSE;
            }
            else {
                *SafeToOpen = TRUE;
            }
        }
        else {

                //
                //  Couldn't read file message OR get context
                //

                DbgPrint("!!! scanner.sys --- failed Reading file OR retreiving context; status(Read) 0x%X\n", status);
            }
        }
     finally {

		if (NULL != buffer) {

			FltFreePoolAlignedWithTag(Instance, buffer, 'nacS');
        }
        
        if (NULL != volume) {

            FltObjectDereference( volume );
        }

		if (NULL != nameInfo) {
			FltReleaseFileNameInformation(nameInfo);
		}
    }

    return status;
}


NTSTATUS ScannerpIsUserSystem(
    _Out_ BOOLEAN* IsUserSystem
    ) 
/*++

Routine Description:

    Checks if the user which initiated the I/O request is NT AUTHORITY\SYSTEM

Arguments

    IsUserSystem - Pointer to a boolean variable which indicates whether the user is NT AUTHORITY\SYSTEM or not.

Return Value

     STATUS_SUCCESS if the function completes successfully.  Otherwise a valid
     NTSTATUS code is returned.

--*/
{

    UNREFERENCED_PARAMETER(IsUserSystem);
    HANDLE hToken;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG TokenUserLength;
    TOKEN_USER* pUserToken = NULL;
    PSID pUserSid = NULL;
    UNICODE_STRING UserSidString;
    UNICODE_STRING NtAuthoritySystemSid = RTL_CONSTANT_STRING(L"S-1-5-18");


    // Open a handle to the user's token of the thread
    status = ZwOpenThreadTokenEx(NtCurrentThread(), GENERIC_READ, TRUE, OBJ_KERNEL_HANDLE, &hToken);

    // If thread is not impersonated, open a handle to the token of the process
    if (!NT_SUCCESS( status )) {
        status = ZwOpenProcessTokenEx(NtCurrentProcess(), GENERIC_READ, OBJ_KERNEL_HANDLE, &hToken);
    }

    // Get the required length for the TokenUser struct
    status = ZwQueryInformationToken(hToken, TokenUser, NULL, 0, &TokenUserLength);

    // Allocate tagged memory pool
    pUserToken = ExAllocatePoolWithTag(NonPagedPool, TokenUserLength, 'ofni');
    if (!pUserToken) {
        status = STATUS_NO_MEMORY;
        goto ScannerpIsUserSystemCleanup;
    }
        
    // Extract the token into the allocated memory pool
    status = ZwQueryInformationToken(hToken, TokenUser, pUserToken, TokenUserLength, &TokenUserLength);
    if (!NT_SUCCESS(status)) {
        goto ScannerpIsUserSystemCleanup;
    }
        
    // Convert the SID to a string, and compare it with NT AUTHORITY\SYSTEM SID
    pUserSid = (PSID)(pUserToken->User.Sid);
    status = RtlConvertSidToUnicodeString(&UserSidString, pUserSid, TRUE);
    if (0 == RtlCompareUnicodeString(&NtAuthoritySystemSid, &UserSidString, FALSE)) {
        *IsUserSystem = TRUE;
    }
    else {
        *IsUserSystem = FALSE;
    }

    status = STATUS_SUCCESS;

ScannerpIsUserSystemCleanup:
    if (NULL != pUserToken) {
        ExFreePoolWithTag(pUserToken, 'ofni');
    }

    return status;
}
