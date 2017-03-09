# VATOPA
Transfer VirtualAddress to PhysicalAddress(PAE，IA-32E)
# Introduce
This demo comprise two parts:   
    First, It runs in the Ring3 that convert the virtual address to driver.      
    Second, the driver, it runs in the Ring0 which translate virtual address to physical address.  
# Tips
The driver only support two paging-mode:PAE, IA-32E, because these modes are common.
# Reference 
《x86/x64体系探索及编程》 No.11 chapter.
