/**
 * @file Vmexit.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief The functions for VM-Exit handler for different exit reasons
 * @details
 * @version 0.1
 * @date 2020-04-11
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

/**
 * @brief Observe HDEC-era VM-exits and re-apply controls if another path cleared them
 *
 * @param VCpu The virtual processor's state
 * @param ExitReason Current VM-exit reason
 * @return VOID
 */
static VOID
HdecDescriptorTableObserveAndRefreshControls(VIRTUAL_MACHINE_STATE * VCpu, UINT32 ExitReason)
{
    IA32_VMX_BASIC_REGISTER VmxBasicMsr = {0};
    CR3_TYPE GuestCr3              = {0};
    UINT64   GuestCr3Masked        = 0;
    UINT32   CurrentProcessId      = 0;
    UINT32   ProcessorControls     = 0;
    UINT32   ExceptionBitmap       = 0;
    BOOLEAN  SecondaryActivePresent = FALSE;
    BOOLEAN  GeneralProtectionBitPresent = FALSE;
    BOOLEAN  HdecProcessObjectMatch = FALSE;
    BOOLEAN  HdecTargetMatch       = FALSE;
    BOOLEAN  CanRefreshControls    = FALSE;

    GuestCr3       = LayoutGetExactGuestProcessCr3();
    GuestCr3Masked = GuestCr3.Flags & ~0xfffULL;
    CurrentProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    HdecProcessObjectMatch =
        (g_HdecDescriptorTableState.ProcessObject != 0 &&
         (UINT64)(ULONG_PTR)PsGetCurrentProcess() == g_HdecDescriptorTableState.ProcessObject);

    if (HdecProcessObjectMatch)
    {
        InterlockedIncrement64(&g_HdecDescriptorTableState.ProcessObjectMatchCount);
    }

    HdecTargetMatch =
        (GuestCr3Masked == g_HdecDescriptorTableState.ProcessCr3 ||
         CurrentProcessId == g_HdecDescriptorTableState.ProcessId ||
         HdecProcessObjectMatch);

    if (HdecTargetMatch)
    {
        InterlockedIncrement64(&g_HdecDescriptorTableState.TargetVmexitCount);
    }

    switch (ExitReason)
    {
    case VMX_EXIT_REASON_EXECUTE_CPUID:
        if (HdecTargetMatch)
        {
            InterlockedIncrement64(&g_HdecDescriptorTableState.TargetCpuidExitCount);
        }

        break;

    default:
        break;
    }

    if (VmxVmread32P(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &ProcessorControls) == 0)
    {
        SecondaryActivePresent =
            (ProcessorControls & IA32_VMX_PROCBASED_CTLS_ACTIVATE_SECONDARY_CONTROLS_FLAG) != 0;
    }

    ExceptionBitmap = HvReadExceptionBitmap();
    GeneralProtectionBitPresent =
        (ExceptionBitmap & (1u << EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT)) != 0;

    CanRefreshControls =
        !VCpu->HdecDescriptorTableRestoreOnMtf &&
        ExitReason != VMX_EXIT_REASON_MONITOR_TRAP_FLAG;

    if (CanRefreshControls && !GeneralProtectionBitPresent)
    {
        HvSetExceptionBitmap(VCpu, EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT);
    }

    if (CanRefreshControls && !SecondaryActivePresent)
    {
        VmxBasicMsr.AsUInt = __readmsr(IA32_VMX_BASIC);
        ProcessorControls |= IA32_VMX_PROCBASED_CTLS_ACTIVATE_SECONDARY_CONTROLS_FLAG;
        ProcessorControls = HvAdjustControls(
            ProcessorControls,
            VmxBasicMsr.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS);

        VmxVmwrite64(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ProcessorControls);
    }
}

/**
 * @brief VM-Exit handler for different exit reasons
 *
 * @param GuestRegs Registers that are automatically saved by AsmVmexitHandler (HOST_RIP)
 * @return BOOLEAN Return True if VMXOFF executed (not in vmx anymore),
 *  or return false if we are still in vmx (so we should use vm resume)
 */
BOOLEAN
VmxVmexitHandler(_Inout_ PGUEST_REGS GuestRegs)
{
    UINT32                  ExitReason = 0;
    BOOLEAN                 Result     = FALSE;
    VIRTUAL_MACHINE_STATE * VCpu       = NULL;

    //
    // *********** SEND MESSAGE AFTER WE SET THE STATE ***********
    //
    VCpu = &g_GuestState[KeGetCurrentProcessorNumberEx(NULL)];

    //
    // Set the registers (general-purpose and XMM)
    //
    VCpu->Regs    = GuestRegs;
    VCpu->XmmRegs = (GUEST_XMM_REGS *)(((CHAR *)GuestRegs) + sizeof(GUEST_REGS));

    //
    // Indicates we are in Vmx root mode in this logical core
    //
    VCpu->IsOnVmxRootMode = TRUE;

    //
    // read the exit reason and exit qualification
    //
    VmxVmread32P(VMCS_EXIT_REASON, &ExitReason);
    ExitReason &= 0xffff;

    //
    // Save the exit reason
    //
    VCpu->ExitReason = ExitReason;

    //
    // Increase the RIP by default
    //
    VCpu->IncrementRip = TRUE;

    //
    // Save the current rip
    //
    __vmx_vmread(VMCS_GUEST_RIP, &VCpu->LastVmexitRip);

    //
    // Set the rsp in general purpose registers structure
    //
    __vmx_vmread(VMCS_GUEST_RSP, &VCpu->Regs->rsp);

    //
    // Read the exit qualification
    //
    VmxVmread32P(VMCS_EXIT_QUALIFICATION, &VCpu->ExitQualification);

    //
    // Debugging purpose
    //
    // LogInfo("VM_EXIT_REASON : 0x%x", ExitReason);
    // LogInfo("VMCS_EXIT_QUALIFICATION : 0x%llx", VCpu->ExitQualification);
    //

    if (g_HdecDescriptorTableState.Enabled &&
        ExitReason != VMX_EXIT_REASON_EXECUTE_VMCALL)
    {
        HdecDescriptorTableObserveAndRefreshControls(VCpu, ExitReason);
    }

    switch (ExitReason)
    {
    case VMX_EXIT_REASON_TRIPLE_FAULT:
    {
        VmxHandleTripleFaults(VCpu);

        break;
    }
        //
        // 25.1.2  Instructions That Cause VM Exits Unconditionally
        // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
        // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
        // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //

    case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
    case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
    case VMX_EXIT_REASON_EXECUTE_VMPTRST:
    case VMX_EXIT_REASON_EXECUTE_VMREAD:
    case VMX_EXIT_REASON_EXECUTE_VMRESUME:
    case VMX_EXIT_REASON_EXECUTE_VMWRITE:
    case VMX_EXIT_REASON_EXECUTE_VMXOFF:
    case VMX_EXIT_REASON_EXECUTE_VMXON:
    case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
    {
        //
        // cf=1 indicate vm instructions fail
        //
        // UINT64 Rflags = 0;
        // __vmx_vmread(VMCS_GUEST_RFLAGS, &Rflags);
        // VmxVmwrite64(VMCS_GUEST_RFLAGS, Rflags | 0x1);

        //
        // Handle unconditional vm-exits (inject #ud)
        //
        EventInjectUndefinedOpcode(VCpu);

        break;
    }
    case VMX_EXIT_REASON_EXECUTE_INVEPT:
    case VMX_EXIT_REASON_EXECUTE_INVVPID:
    case VMX_EXIT_REASON_EXECUTE_GETSEC:
    case VMX_EXIT_REASON_EXECUTE_INVD:
    {
        //
        // Handle unconditional vm-exits (inject #ud)
        //
        EventInjectUndefinedOpcode(VCpu);

        break;
    }
    case VMX_EXIT_REASON_MOV_CR:
    {
        //
        // Handle vm-exit, events, dispatches and perform changes from CR access
        //
        DispatchEventMovToFromControlRegisters(VCpu);

        break;
    }
    case VMX_EXIT_REASON_EXECUTE_RDMSR:
    {
        //
        // Handle vm-exit, events, dispatches and perform MSR read
        //
        DispatchEventRdmsr(VCpu);

        break;
    }
    case VMX_EXIT_REASON_EXECUTE_WRMSR:
    {
        //
        // Handle vm-exit, events, dispatches and perform changes
        //
        DispatchEventWrmsr(VCpu);

        break;
    }
    case VMX_EXIT_REASON_IO_SMI:
    case VMX_EXIT_REASON_SMI:
    {
        //
        // Handle SMI and IO-SMI (should never happen in normal cases)
        //
        LogInfo("VM-exit reason SMM %llx | qual: %llx", ExitReason, VCpu->ExitQualification);

        break;
    }
    case VMX_EXIT_REASON_EXECUTE_CPUID:
    {
        //
        // Dispatch and trigger the CPUID instruction events
        //
        DispatchEventCpuid(VCpu);

        break;
    }

    case VMX_EXIT_REASON_EXECUTE_IO_INSTRUCTION:
    {
        //
        // Dispatch and trigger the I/O instruction events
        //
        DispatchEventIO(VCpu);

        break;
    }
    case VMX_EXIT_REASON_EPT_VIOLATION:
    {
        //
        // Handle EPT violation
        //
        if (EptHandleEptViolation(VCpu) == FALSE)
        {
            LogError("Err, there were errors in handling EPT violation");
        }

        break;
    }
    case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
    {
        //
        // Handle EPT misconfiguration (should never happen)
        //
        EptHandleMisconfiguration();

        break;
    }
    case VMX_EXIT_REASON_EXECUTE_VMCALL:
    {
        //
        // Handle vm-exits of VMCALLs
        //
        DispatchEventVmcall(VCpu);

        break;
    }
    case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
    {
        //
        // Handle the EXCEPTION injection/emulation
        //
        DispatchEventException(VCpu);

        break;
    }
    case VMX_EXIT_REASON_EXTERNAL_INTERRUPT:
    {
        //
        // Call the external-interrupt handler
        //
        DispatchEventExternalInterrupts(VCpu);

        break;
    }
    case VMX_EXIT_REASON_INTERRUPT_WINDOW:
    {
        //
        // Call the interrupt-window exiting handler to re-inject the previous
        // interrupts or disable the interrupt-window exiting bit
        //
        IdtEmulationHandleInterruptWindowExiting(VCpu);

        break;
    }
    case VMX_EXIT_REASON_NMI_WINDOW:
    {
        //
        // Call the NMI-window exiting handler
        //
        IdtEmulationHandleNmiWindowExiting(VCpu);

        break;
    }
    case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
    {
        //
        // General handler to monitor trap flags (MTF)
        //
        MtfHandleVmexit(VCpu);

        break;
    }
    case VMX_EXIT_REASON_EXECUTE_HLT:
    {
        //
        // We don't wanna halt
        //

        //
        //__halt();
        //
        break;
    }
    case VMX_EXIT_REASON_EXECUTE_RDTSC:
    case VMX_EXIT_REASON_EXECUTE_RDTSCP:

    {
        //
        // Check whether we are allowed to change the registers
        // and emulate rdtsc or not
        //
        DispatchEventTsc(VCpu, ExitReason == VMX_EXIT_REASON_EXECUTE_RDTSCP ? TRUE : FALSE);

        break;
    }
    case VMX_EXIT_REASON_EXECUTE_RDPMC:
    {
        //
        // Handle RDPMC's events, triggers and dispatches (emulate RDPMC)
        //
        DispatchEventRdpmc(VCpu);

        break;
    }
    case VMX_EXIT_REASON_GDTR_IDTR_ACCESS:
    case VMX_EXIT_REASON_LDTR_TR_ACCESS:
    {
        //
        // Handle descriptor-table exiting transparently with MTF pass-through
        //
        DispatchEventDescriptorTableAccess(VCpu, ExitReason);

        break;
    }
    case VMX_EXIT_REASON_MOV_DR:
    {
        //
        // Trigger, dispatch and handle the event
        //
        DispatchEventMov2DebugRegs(VCpu);

        break;
    }
    case VMX_EXIT_REASON_EXECUTE_XSETBV:
    {
        //
        // Dispatch and trigger the XSETBV instruction events
        //
        DispatchEventXsetbv(VCpu);

        break;
    }
    case VMX_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
    {
        //
        // Handle the VMX preemption timer vm-exit
        //
        VmxHandleVmxPreemptionTimerVmexit(VCpu);

        break;
    }
    case VMX_EXIT_REASON_PAGE_MODIFICATION_LOG_FULL:
    {
        //
        // Handle page-modification log
        //
        DirtyLoggingHandleVmexits(VCpu);

        break;
    }
    default:
    {
        //
        // Not handled vm-exit
        //
        LogError("Err, unknown vmexit, reason : 0x%llx", ExitReason);

        break;
    }
    }

    //
    // Check whether we need to increment the guest's ip or not
    // Also, we should not increment rip if a vmxoff executed
    //
    if (!VCpu->VmxoffState.IsVmxoffExecuted && VCpu->IncrementRip)
    {
        //
        // If we are in transparent-mode, then we need to handle the trap flag as the result
        // of an anti-hypervisor technique of using the trap flag after a VM-exit
        // to detect the hypervisor
        //
        if (g_CheckForFootprints)
        {
            TransparentCheckAndTrapFlagAfterVmexit();
        }

        HvResumeToNextInstruction();
    }

    //
    // Check for vmxoff request
    //
    if (VCpu->VmxoffState.IsVmxoffExecuted)
    {
        Result = TRUE;
    }

    //
    // Set indicator of Vmx non root mode to false
    //
    VCpu->IsOnVmxRootMode = FALSE;

    //
    // By default it's FALSE, if we want to exit vmx then it's TRUE
    //
    return Result;
}
