DEFAULT REL
 SECTION .text
 global ASM_PFX(CpuIceBreakpoint)
 ASM_PFX(CpuIceBreakpoint):
    int1
    ret
    
