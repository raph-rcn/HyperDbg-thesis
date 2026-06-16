/**
 * @file descmon.cpp
 * @author HyperDbg contributors
 * @brief !descmon command
 * @details Native descriptor-table instruction monitor command.
 * @version 0.1
 * @date 2026-06-07
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

/**
 * @brief Convert a descriptor-table instruction token to the event filter mask
 *
 * @param Token Target command token
 * @param InstructionMask Output instruction mask
 * @return BOOLEAN TRUE if the token is a known instruction filter
 */
static BOOLEAN
CommandDescmonParseInstructionFilter(CommandToken Token, UINT64 * InstructionMask)
{
    if (CompareLowerCaseStrings(Token, "all"))
    {
        *InstructionMask = DESCRIPTOR_TABLE_INSTRUCTION_ALL;
        return TRUE;
    }
    else if (CompareLowerCaseStrings(Token, "sidt"))
    {
        *InstructionMask = DESCRIPTOR_TABLE_INSTRUCTION_SIDT;
        return TRUE;
    }
    else if (CompareLowerCaseStrings(Token, "sgdt"))
    {
        *InstructionMask = DESCRIPTOR_TABLE_INSTRUCTION_SGDT;
        return TRUE;
    }
    else if (CompareLowerCaseStrings(Token, "sldt"))
    {
        *InstructionMask = DESCRIPTOR_TABLE_INSTRUCTION_SLDT;
        return TRUE;
    }
    else if (CompareLowerCaseStrings(Token, "str"))
    {
        *InstructionMask = DESCRIPTOR_TABLE_INSTRUCTION_STR;
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief help of the !descmon command
 *
 * @return VOID
 */
VOID
CommandDescmonHelp()
{
    ShowMessages("!descmon : monitors execution of descriptor-table instructions.\n\n");

    ShowMessages("syntax : \t!descmon [all|sidt|sgdt|sldt|str] [pid ProcessId (hex)] [name ImageFileName (string)] [core CoreId (hex)] "
                 "[imm IsImmediate (yesno)] [sc EnableShortCircuiting (onoff)] [stage CallingStage (prepostall)] "
                 "[buffer PreAllocatedBuffer (hex)] [script { Script (string) }] [asm condition { Condition (assembly/hex) }] "
                 "[asm code { Code (assembly/hex) }] [output {OutputName (string)}]\n");

    ShowMessages("\n");
    ShowMessages("\t\te.g : !descmon\n");
    ShowMessages("\t\te.g : !descmon all\n");
    ShowMessages("\t\te.g : !descmon sidt pid 400\n");
    ShowMessages("\t\te.g : !descmon sgdt core 2 pid 400\n");
    ShowMessages("\t\te.g : !descmon script { printf(\"descriptor-table instruction mask: %%llx\\n\", $context); }\n");
    ShowMessages("\t\te.g : !descmon asm code { nop; nop; nop }\n");
}

/**
 * @brief handler of !descmon command
 *
 * @param CommandTokens
 * @param Command
 *
 * @return VOID
 */
VOID
CommandDescmon(vector<CommandToken> CommandTokens, string Command)
{
    PDEBUGGER_GENERAL_EVENT_DETAIL     Event                 = NULL;
    PDEBUGGER_GENERAL_ACTION           ActionBreakToDebugger = NULL;
    PDEBUGGER_GENERAL_ACTION           ActionCustomCode      = NULL;
    PDEBUGGER_GENERAL_ACTION           ActionScript          = NULL;
    UINT32                             EventLength;
    UINT64                             InstructionMask             = DESCRIPTOR_TABLE_INSTRUCTION_ALL;
    BOOLEAN                            HasInstructionFilter        = FALSE;
    UINT32                             ActionBreakToDebuggerLength = 0;
    UINT32                             ActionCustomCodeLength      = 0;
    UINT32                             ActionScriptLength          = 0;
    DEBUGGER_EVENT_PARSING_ERROR_CAUSE EventParsingErrorCause;

    UNREFERENCED_PARAMETER(Command);

    //
    // Interpret and fill the general event and action fields
    //
    if (!InterpretGeneralEventAndActionsFields(
            &CommandTokens,
            DESCRIPTOR_TABLE_INSTRUCTION_EXECUTION,
            &Event,
            &EventLength,
            &ActionBreakToDebugger,
            &ActionBreakToDebuggerLength,
            &ActionCustomCode,
            &ActionCustomCodeLength,
            &ActionScript,
            &ActionScriptLength,
            &EventParsingErrorCause))
    {
        return;
    }

    //
    // Interpret the optional descriptor-table instruction selector.
    //
    for (auto Section : CommandTokens)
    {
        if (CompareLowerCaseStrings(Section, "!descmon"))
        {
            continue;
        }
        else if (!HasInstructionFilter && CommandDescmonParseInstructionFilter(Section, &InstructionMask))
        {
            HasInstructionFilter = TRUE;
        }
        else
        {
            ShowMessages("unknown parameter '%s'\n\n",
                         GetCaseSensitiveStringFromCommandToken(Section).c_str());

            CommandDescmonHelp();

            FreeEventsAndActionsMemory(Event, ActionBreakToDebugger, ActionCustomCode, ActionScript);
            return;
        }
    }

    Event->Options.OptionalParam1 = InstructionMask;

    //
    // Send the ioctl to the kernel for event registration
    //
    if (!SendEventToKernel(Event, EventLength))
    {
        FreeEventsAndActionsMemory(Event, ActionBreakToDebugger, ActionCustomCode, ActionScript);
        return;
    }

    //
    // Add the event action to the kernel
    //
    if (!RegisterActionToEvent(Event,
                               ActionBreakToDebugger,
                               ActionBreakToDebuggerLength,
                               ActionCustomCode,
                               ActionCustomCodeLength,
                               ActionScript,
                               ActionScriptLength))
    {
        FreeEventsAndActionsMemory(Event, ActionBreakToDebugger, ActionCustomCode, ActionScript);
        return;
    }
}
