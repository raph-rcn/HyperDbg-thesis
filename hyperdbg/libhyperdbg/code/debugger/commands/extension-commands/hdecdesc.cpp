/**
 * @file hdecdesc.cpp
 * @brief Private HDEC descriptor-table exiting command
 *
 */
#include "pch.h"

//
// Global Variables
//
extern BOOLEAN g_IsSerialConnectedToRemoteDebuggee;

/**
 * @brief help of the !hdecdesc command
 *
 * @return VOID
 */
VOID
CommandHdecDescHelp()
{
    ShowMessages("!hdecdesc : enables or disables descriptor instruction telemetry.\n\n");

    ShowMessages("syntax : \t!hdecdesc enable pid ProcessId (hex) [sample_id SampleId (string)]\n");
    ShowMessages("syntax : \t!hdecdesc disable\n");
    ShowMessages("syntax : \t!hdecdesc query\n");

    ShowMessages("\n");
    ShowMessages("\t\te.g : !hdecdesc enable pid 2110 sample_id \"vmaware32\"\n");
    ShowMessages("\t\te.g : !hdecdesc disable\n");
}

/**
 * @brief Copy a command string into a fixed HDEC field
 *
 * @param Destination
 * @param DestinationSize
 * @param Source
 *
 * @return VOID
 */
static VOID
CommandHdecDescCopyString(CHAR * Destination, size_t DestinationSize, const string & Source)
{
    if (Destination == NULL || DestinationSize == 0)
    {
        return;
    }

    memset(Destination, 0, DestinationSize);
    strncpy_s(Destination, DestinationSize, Source.c_str(), _TRUNCATE);
}

/**
 * @brief Send HDEC descriptor-table request
 *
 * @param Request
 *
 * @return BOOLEAN
 */
static BOOLEAN
CommandHdecDescSendRequest(PHDEC_DESCRIPTOR_TABLE_REQUEST Request)
{
    BOOL  Status;
    ULONG ReturnedLength;

    if (g_IsSerialConnectedToRemoteDebuggee)
    {
        ShowMessages("err, !hdecdesc is only supported in local debugger mode\n");
        return FALSE;
    }

    AssertShowMessageReturnStmt(g_DeviceHandle, ASSERT_MESSAGE_DRIVER_NOT_LOADED, AssertReturnFalse);

    Status = DeviceIoControl(
        g_DeviceHandle,
        IOCTL_HDEC_DESCRIPTOR_TABLE_EVENT,
        Request,
        SIZEOF_HDEC_DESCRIPTOR_TABLE_REQUEST,
        Request,
        SIZEOF_HDEC_DESCRIPTOR_TABLE_REQUEST,
        &ReturnedLength,
        NULL);

    if (!Status)
    {
        ShowMessages("ioctl failed with code 0x%x\n", GetLastError());
        return FALSE;
    }

    if (Request->KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
    {
        ShowErrorMessage(Request->KernelStatus);
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief !hdecdesc command handler
 *
 * @param CommandTokens
 * @param Command
 *
 * @return VOID
 */
VOID
CommandHdecDesc(vector<CommandToken> CommandTokens, string Command)
{
    HDEC_DESCRIPTOR_TABLE_REQUEST Request      = {0};
    BOOLEAN                       IsPidFound  = FALSE;
    string                        SampleId    = "";
    UINT32                        TargetPid   = 0;

    UNREFERENCED_PARAMETER(Command);

    if (CommandTokens.size() < 2)
    {
        ShowMessages("incorrect use of the '%s'\n\n",
                     GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
        CommandHdecDescHelp();
        return;
    }

    if (CompareLowerCaseStrings(CommandTokens.at(1), "enable"))
    {
        Request.RequestType = HDEC_DESCRIPTOR_TABLE_REQUEST_ENABLE;

        for (size_t Index = 2; Index < CommandTokens.size(); Index++)
        {
            if (CompareLowerCaseStrings(CommandTokens.at(Index), "pid"))
            {
                Index++;

                if (Index >= CommandTokens.size() ||
                    !ConvertTokenToUInt32(CommandTokens.at(Index), &TargetPid))
                {
                    ShowMessages("incorrect use of the '%s'\n\n",
                                 GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
                    CommandHdecDescHelp();
                    return;
                }

                IsPidFound = TRUE;
            }
            else if (CompareLowerCaseStrings(CommandTokens.at(Index), "sample_id") ||
                     CompareLowerCaseStrings(CommandTokens.at(Index), "sample"))
            {
                Index++;

                if (Index >= CommandTokens.size())
                {
                    ShowMessages("incorrect use of the '%s'\n\n",
                                 GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
                    CommandHdecDescHelp();
                    return;
                }

                SampleId = GetCaseSensitiveStringFromCommandToken(CommandTokens.at(Index));
            }
            else
            {
                ShowMessages("incorrect use of the '%s'\n\n",
                             GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
                CommandHdecDescHelp();
                return;
            }
        }

        if (!IsPidFound)
        {
            ShowMessages("incorrect use of the '%s'\n\n",
                         GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
            CommandHdecDescHelp();
            return;
        }

        Request.ProcessId = TargetPid;
        CommandHdecDescCopyString(Request.SampleId, sizeof(Request.SampleId), SampleId);

        if (CommandHdecDescSendRequest(&Request))
        {
            ShowMessages("hdecdesc descriptor-table detector enabled for pid %x cr3 %llx process \"%s\" sample_id \"%s\"\n",
                         Request.ProcessId,
                         Request.ProcessCr3,
                         Request.ProcessName,
                         Request.SampleId);
        }
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(1), "disable"))
    {
        if (CommandTokens.size() != 2)
        {
            ShowMessages("incorrect use of the '%s'\n\n",
                         GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
            CommandHdecDescHelp();
            return;
        }

        Request.RequestType = HDEC_DESCRIPTOR_TABLE_REQUEST_DISABLE;

        if (CommandHdecDescSendRequest(&Request))
        {
            ShowMessages("hdecdesc descriptor-table detector disabled\n");
        }
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(1), "query"))
    {
        if (CommandTokens.size() != 2)
        {
            ShowMessages("incorrect use of the '%s'\n\n",
                         GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
            CommandHdecDescHelp();
            return;
        }

        Request.RequestType = HDEC_DESCRIPTOR_TABLE_REQUEST_QUERY;

        if (CommandHdecDescSendRequest(&Request))
        {
            ShowMessages("hdecdesc descriptor instruction telemetry is supported\n");
        }
    }
    else
    {
        ShowMessages("incorrect use of the '%s'\n\n",
                     GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
        CommandHdecDescHelp();
    }
}
