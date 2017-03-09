#ifndef CXX_COMMON_H
#	include "common.h"
#endif

// 链接器可能需要 /SAFESEH:NO 
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	UNICODE_STRING uniDeviceName = { 0 };
	UNICODE_STRING uniLinkName = { 0 };
	PDEVICE_OBJECT pDeviceObject = NULL;
	NTSTATUS	   NtStatus = STATUS_SUCCESS;
	int i = 0;

	RtlInitUnicodeString(&uniDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uniLinkName, LINK_NAME);

	NtStatus = IoCreateDevice(DriverObject, 0, &uniDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(NtStatus))
	{
		return NtStatus;
	}

	NtStatus = IoCreateSymbolicLink(&uniLinkName, &uniDeviceName);
	if (!NT_SUCCESS(NtStatus))
	{
		IoDeleteDevice(pDeviceObject);
		return NtStatus;
	}

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DefaultPassThrough;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlPassThrough;

	DriverObject->DriverUnload = UnloadDriver;

	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING uniLinkName = { 0 };
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT pCurrentDeviceObject = NULL;
	PDEVICE_OBJECT pNextDeviceObject = NULL;

	if (DriverObject->DeviceObject != NULL)
	{
		RtlInitUnicodeString(&uniLinkName, LINK_NAME);
		NtStatus = IoDeleteSymbolicLink(&uniLinkName);

		IoDeleteDevice(DriverObject->DeviceObject);

		pCurrentDeviceObject = DriverObject->DeviceObject;
		while (pCurrentDeviceObject != NULL)
		{
			pNextDeviceObject = pCurrentDeviceObject->NextDevice;

			IoDeleteDevice(pCurrentDeviceObject);
			pCurrentDeviceObject = pNextDeviceObject;
		}
	}

	return;
}

NTSTATUS DefaultPassThrough(PDEVICE_OBJECT DeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS ControlPassThrough(PDEVICE_OBJECT DeviceObject, PIRP pIrp)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpSp = NULL;
	ULONG	ulIoControlCode = 0;
	PVOID	InputBuffer = NULL;
	PVOID	OutputBuffer = NULL;
	ULONG	ulInputBufferLength = 0;
	ULONG	ulOutputBufferLength = 0;

	ULONG32	ulMaxPhysicalAddressBit = 0;
	ULONG64	ulMaxPhysicalAddress = 0;
	VIRTUAL_ADDRESS VirtualAddress = { 0 };
	VIRTUAL_ADDRESS_IA_32E VirtualAddressIA32E = { 0 };

	ULONG32		PageMapLevel4EntryIndex = 0;		// PML4T - PML4E 
	ULONG64		PageMapLevel4TableBasePA = 0;
	PULONG_PTR pPageMapLevel4EntryVA = 0;

	ULONG32		PageDirPointTableEntryIndex = 0;	// PDPT - PDPTE
	ULONG_PTR	PageDirPointTableBasePA = 0;		
	PULONG_PTR	pPageDirPointTableEntryVA = 0;
	
	ULONG32		PageDirEntryIndex = 0;				// PDT - PDE
	ULONG_PTR	PageDirTableBasePA = 0;
	PULONG_PTR  pPageDirEntryVA = 0;

	ULONG32		PageTableEntryIndex = 0;			// PT - PTE
	ULONG_PTR	PageTableBasePA = 0;
	PULONG_PTR  pPageTableEntryVA = 0;

	ULONG64		PageOffset = 0;
	ULONG_PTR	PageBasePA = 0;
	PULONG_PTR	pPageAddressVA = 0;

	ULONG_PTR	ulPhysicalAddressPA = 0;
	PULONG_PTR  pPhysicalAddressVA = 0;
	
	PHYSICAL_ADDRESS PhysicalAddress = { 0 };	// LARGE_INTEGER = PHYSICAL_ADDRESS	

	PMDL pVirtualAddressMDL = NULL;
	PVOID pVAKernelVA = NULL;

	INT i = 0;

	pIrpSp = IoGetCurrentIrpStackLocation(pIrp);
	InputBuffer = pIrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	OutputBuffer = pIrp->UserBuffer;
	ulInputBufferLength = pIrpSp->Parameters.DeviceIoControl.InputBufferLength;
	ulOutputBufferLength = pIrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ulIoControlCode = pIrpSp->Parameters.DeviceIoControl.IoControlCode;

	switch (ulIoControlCode)
	{
	case CTL_PAE:	// PAE 其实也应该用8字节的长1度来处理 - 有待完善
	{
		VirtualAddress.ulVirtualAddress = *((PULONG)InputBuffer);
		DbgPrint("传入的虚拟地址:0x%p\r\n", VirtualAddress.ulVirtualAddress);
		// 得到MaxPhysicalAddress- 64位下的PAE需要用到 32位下的PAE并不需要
		ulMaxPhysicalAddressBit = GetMaxPhysicalAddress();
		for (i = 12; i < ulMaxPhysicalAddressBit; i++)
		{
			ulMaxPhysicalAddress += pow(2, i);
		}
		DbgPrint("当前系统最高物理地址%d位,构造成的与值:%llx", ulMaxPhysicalAddressBit, ulMaxPhysicalAddress);

		// 申请个MDL 把VirtualAddress给锁上 - 可能需要
		//pVirtualAddressMDL = IoAllocateMdl((PVOID)(VirtualAddress.ulVirtualAddress), ulInputBufferLength, FALSE, FALSE, NULL);
		//MmBuildMdlForNonPagedPool(pVirtualAddressMDL);
		
		// 重复步骤
		// 1.上一步或者CR3中得到表的物理地址
		// 2.得到索引
		// 3.计算出我们要找的表项的物理地址
		// 4.映射虚拟地址 - 访问得到下一个表的物理基地址 
		// 5.回到第一步
		// 直到得到页的首地址后，直接加偏移 映射 访问 得到值

		// PDPT -> PDT 2位index	
		PageDirPointTableBasePA = __readcr3();							// 1 得到CR3的值
		PageDirPointTableBasePA = PageDirPointTableBasePA & 0xFFFFFFE0;	// 去掉低五位

		PageDirPointTableEntryIndex = VirtualAddress.VirtualAddressForm.PageDirPointTableIndex;		// 2 取出 PDPT 索引
		// 实际去映射的地址 应该是最后表项的地址 所以应该加好偏移再去映射
		PhysicalAddress.LowPart = PageDirPointTableBasePA + 8 * PageDirPointTableEntryIndex;			// 3
		// CR3是物理地址 - 我们想要访问只能找一块虚拟地址映射到它 通过访问这块虚拟地址来访问
		pPageDirPointTableEntryVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);	// 4
		DbgPrint("CR3(PageDirPointTableBase)\t物理地址:0x%p\t表项的索引:%d\t表项的物理地址:0x%p\t表项虚拟映射地址:0x%p\r\n", 
				 PageDirPointTableBasePA, PageDirPointTableEntryIndex, PageDirPointTableBasePA + 8 * PageDirPointTableEntryIndex, pPageDirPointTableEntryVA);
		
		PageDirTableBasePA = *pPageDirPointTableEntryVA & 0xFFFFF000;	     // 5. 访问得到下一个表的物理基地址，抹掉最后三位,PDPT中的每个表项是一个PDT的基地址
		
		// PDT -> PT	9位索引
		PageDirEntryIndex = VirtualAddress.VirtualAddressForm.PageDirTableIndex;		// 2 取出PDT索引
		PhysicalAddress.LowPart = PageDirTableBasePA + 8 * PageDirEntryIndex;			// 3
		pPageDirEntryVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);		// 4
		DbgPrint("PageDirectoryTableBase\t物理地址:0x%p\t表项的索引:%d\t表项的物理地址:0x%p\t虚拟映射地址:0x%p\r\n", 
			     PageDirTableBasePA, PageDirEntryIndex, PageDirTableBasePA + 8 * PageDirEntryIndex, pPageDirEntryVA);
		// 4K - 2M 页面分别处理 判断 PDE.PS([7])
		if (*pPageDirEntryVA & 0x00000080)
		{
			DbgPrint("当前页面采用2M页面映射方式\r\n");
			PageBasePA = *pPageDirEntryVA & 0xFFE00000;	// [MAXPHYSICAL:21] PDE 直接取得 PageBase
			ulPhysicalAddressPA = PageBasePA + VirtualAddress.VirtualAddressForm.Page2M.ul2MPageOffset;	// 加偏移
			PhysicalAddress.LowPart = ulPhysicalAddressPA;
			pPhysicalAddressVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);

			DbgPrint("PageBase\t物理地址:0x%p\t页偏移:0x%p\t最终物理地址:0x%p\t映射虚拟地址:0x%p\t地址数值:%s\r\n",
				PageBasePA, VirtualAddress.VirtualAddressForm.Page2M.ul2MPageOffset, ulPhysicalAddressPA, pPhysicalAddressVA, pPhysicalAddressVA);

			*((PULONG)OutputBuffer) = ulPhysicalAddressPA;
		}
		else
		{
			DbgPrint("当前页面采用4K页面映射方式\r\n");
			PageTableBasePA = *pPageDirEntryVA & 0xFFFFF000;			// 5 访问得到下一个表的物理基地址，抹掉最后是三位,PDT的每个表项是一个PD的基地址
																			
			PageTableEntryIndex = VirtualAddress.VirtualAddressForm.Page4K.PageTableIndex;	// PT -> Page  9位索引
			PhysicalAddress.LowPart = PageTableBasePA + 8 * PageTableEntryIndex;
			pPageTableEntryVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
			DbgPrint("PageTableBase\t物理地址:0x%p\t表项的索引:%x\t表项的物理地址:0x%p\t虚拟映射地址:0x%p\r\n",
				PageTableBasePA, PageTableEntryIndex, PageTableBasePA + 8 * PageTableEntryIndex, pPageTableEntryVA);

			PageBasePA = *pPageTableEntryVA & 0xFFFFF000;

			// 最后加上页内偏移 12位偏移
			ulPhysicalAddressPA = PageBasePA + VirtualAddress.VirtualAddressForm.Page4K.ul4KPageOffset;
			PhysicalAddress.LowPart = ulPhysicalAddressPA;
			pPhysicalAddressVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);

			DbgPrint("PageBase\t物理地址:0x%p\t页偏移:0x%p\t最终物理地址:0x%p\t映射虚拟地址:0x%p\t地址数值:%s\r\n",
				PageBasePA, VirtualAddress.VirtualAddressForm.Page4K.ul4KPageOffset, ulPhysicalAddressPA, pPhysicalAddressVA, pPhysicalAddressVA);

			*((PULONG)OutputBuffer) = ulPhysicalAddressPA;
		}
		//IoFreeMdl(pVirtualAddressMDL);

		pIrp->IoStatus.Information = ulOutputBufferLength;
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		break;
	}
	case CTL_IA32E:
	{
		VirtualAddressIA32E.ulVirtualAddress = *((PULONG64)InputBuffer);
		DbgPrint("传入的虚拟地址:%llx\r\n", VirtualAddress.ulVirtualAddress);
		// 得到 MaxPhysicalAddress
		ulMaxPhysicalAddressBit = GetMaxPhysicalAddress();
		for (i = 12; i < ulMaxPhysicalAddressBit; i++)
		{
			ulMaxPhysicalAddress += pow(2, i);
		}
		DbgPrint("当前系统最高物理地址%d位,构造成的与值:%llx", ulMaxPhysicalAddressBit, ulMaxPhysicalAddress);

		// 1.得到基地址
		// 2.进行与值操作，得到真正地址
		// 3.从虚拟地址中得到索引
		// 4.得到要找的表项的物理地址
		// 5.映射物理地址 - 得到映射虚拟地址 -> 访问得到下一根表的基地址 回到1
		// 直到得到页面基地址 + 页面偏移 就得到实际地址 再映射一次 访问即可

		// CR3 -> PML4T Base -> PML4E -> PDPT Base
		PageMapLevel4TableBasePA = __readcr3();					// 1.取基地址
		PageMapLevel4TableBasePA &= ulMaxPhysicalAddress;		// 2.与 MaxPhyAddr， 去掉头部
		PageMapLevel4TableBasePA &= 0xFFFFFFFFFFFFF000;			// 2.去掉低三位      4K对齐
		PageMapLevel4EntryIndex = VirtualAddressIA32E.VirtualAddressForm.PageMapLevel4EntryIndex;	// 3.得到索引
		PhysicalAddress.QuadPart = PageMapLevel4TableBasePA + 8 * PageMapLevel4EntryIndex;			// 4.得到表项物理地址
		pPageMapLevel4EntryVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);	// 5.表项映射
		DbgPrint("CR3(PageMapLevel4TableBase)\t物理地址:%#llx\t表项的索引:%d\t表项的物理地址:%#llx\t表项虚拟映射地址:%#llx\r\n",
			PageMapLevel4TableBasePA, PageMapLevel4EntryIndex, PageMapLevel4TableBasePA + 8 * PageMapLevel4EntryIndex, pPageMapLevel4EntryVA);

		// PDPT Base -> PDPTE    -> PDT Base / 1G Page Base
		PageDirPointTableBasePA = *pPageMapLevel4EntryVA;		// 访问上一个表项 得到下一个表的基地址
		PageDirPointTableBasePA &= ulMaxPhysicalAddress;
		PageDirPointTableBasePA &= 0xFFFFFFFFFFFFF000;
		PageDirPointTableEntryIndex = VirtualAddressIA32E.VirtualAddressForm.PageDirPointTableEntryIndex;
		PhysicalAddress.QuadPart = PageDirPointTableBasePA + 8 * PageDirPointTableEntryIndex;
		pPageDirPointTableEntryVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
		DbgPrint("PageDirPointTableBase\t物理地址:%#llx\t表项的索引:%d\t表项的物理地址:%#llx\t表项虚拟映射地址:%#llx\r\n",
			PageDirPointTableBasePA, PageDirPointTableEntryIndex, PageDirPointTableBasePA + 8 * PageDirPointTableEntryIndex, pPageDirPointTableEntryVA);
		
		PageDirTableBasePA = *pPageDirPointTableEntryVA;	
		if (PageDirTableBasePA & 0x0000000000000080)		// 判断PDPTE第七位 判断是否是 1G页面映射方式
		{
			DbgPrint("当前页面采用1G页面映射方式\r\n");
			// PDPTE -> 1G Page Base + Offset
			PageBasePA = PageDirTableBasePA & ulMaxPhysicalAddress;	// PageDirTableBasePA 已经是未进处理的 Page Base值，因为它是PDPTE表项的值。我直接那这个变量进行了去头操作。
			PageBasePA &= 0xFFFFFFFF30000000;
			ulPhysicalAddressPA = PageBasePA + VirtualAddressIA32E.VirtualAddressForm.Page1G.ul1GPageOffset;
			pPhysicalAddressVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
			DbgPrint("PageBase\t物理地址:%#llx\t页偏移:0x%x\t最终物理地址:%#llx\t映射虚拟地址:%#llx\t地址数值:%s\r\n",
				PageBasePA, VirtualAddressIA32E.VirtualAddressForm.Page1G.ul1GPageOffset, ulPhysicalAddressPA, pPhysicalAddressVA, pPhysicalAddressVA);
		}
		// 4K / 2M 页面映射方式 -> 继续得到PDT Base
		else
		{
			// PDT Base -> PDE		-> PT Base / 2M Page Base
			PageDirTableBasePA &= ulMaxPhysicalAddress;
			PageDirTableBasePA &= 0xFFFFFFFFFFFFF000;
			PageDirEntryIndex = VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.PageDirectoryEntryIndex;
			PhysicalAddress.QuadPart = PageDirPointTableBasePA + 8 * PageDirEntryIndex;
			pPageDirEntryVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
			DbgPrint("PageDirectoryTableBase\t物理地址:%#llx\t表项的索引:%d\t表项的物理地址:%#llx\t虚拟映射地址:%#llx\r\n",
				PageDirTableBasePA, PageDirEntryIndex, PageDirTableBasePA + 8 * PageDirEntryIndex, pPageDirEntryVA);

			PageTableBasePA = *pPageDirEntryVA;
			if (PageTableBasePA & 0x0000000000000080)	// 判断PDE第七位 判断是否是 2M页面映射方式
			{
				DbgPrint("当前页面采用2M页面映射方式\r\n");
				// PDE -> 2M Page Base + Offset
				PageBasePA = PageTableBasePA & ulMaxPhysicalAddress;	// PageTableBasePA 已经是未进处理的Base值，我这里偷懒直接拿来开始进行第一步处理。然后进行赋值
				PageBasePA &= 0xFFFFFFFFFFE00000;
				ulPhysicalAddressPA = PageBasePA + VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.Page2M.ul2MPageOffset;
				pPhysicalAddressVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
				DbgPrint("PageBase\t物理地址:%#llx\t页偏移:0x%x\t最终物理地址:%#llx\t映射虚拟地址:%#llx\t地址数值:%s\r\n",
					PageBasePA, VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.Page2M.ul2MPageOffset, ulPhysicalAddressPA, pPhysicalAddressVA, pPhysicalAddressVA);
			}
			// 4K 页面映射方式 -> 继续得到PT Base
			else
			{
				DbgPrint("当前页面采用4K页面映射方式\r\n");
				// PT -> PTE -> 4K Page Base
				PageTableBasePA &= ulMaxPhysicalAddress;
				PageTableBasePA &= 0xFFFFFFFFFFFFF000;
				PageTableEntryIndex = VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.Page4K.PageTableEntryIndex;
				PhysicalAddress.QuadPart = PageTableBasePA + 8 * PageTableEntryIndex;
				pPageTableEntryVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
				DbgPrint("PageTableBase\t物理地址:%#llx\t表项的索引:%x\t表项的物理地址:%#llx\t虚拟映射地址:%#llx\r\n",
					PageTableBasePA, PageTableEntryIndex, PageTableBasePA + 8 * PageTableEntryIndex, pPageTableEntryVA);

				// 4K Page Base + Offset
				PageBasePA = *pPageTableEntryVA;
				PageBasePA &= 0xFFFFFFFFFFFFF000;
				PageBasePA &= ulMaxPhysicalAddress;
				ulPhysicalAddressPA = PageBasePA + VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.Page4K.ul4KPageOffset;
				PhysicalAddress.QuadPart = ulPhysicalAddressPA;
				pPhysicalAddressVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
				DbgPrint("PageBase\t物理地址:%#llx\t页偏移:0x%x\t最终物理地址:%#llx\t映射虚拟地址:%#llx\t地址数值:%s\r\n",
					PageBasePA, VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.Page4K.ul4KPageOffset, ulPhysicalAddressPA, pPhysicalAddressVA, pPhysicalAddressVA);
			}
		}

		*((PULONG64)OutputBuffer) = ulPhysicalAddressPA;

		pIrp->IoStatus.Information = ulOutputBufferLength;
		pIrp->IoStatus.Status = STATUS_SUCCESS;

		break;
	}
	default:
	{
		pIrp->IoStatus.Information = ulOutputBufferLength;
		pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		break;
	}
	}

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// 得到支持最大物理地址支持
INT GetMaxPhysicalAddress()
{
	INT CpuInfo[4] = { 0 };
	ULONG32 MaxPhyAddr = 0;
	__cpuidex(CpuInfo, 0x80000000, 32);
	if (CpuInfo[0] == 0x80000008)		// 支持 0x80000008 查询吗?
	{
		RtlZeroMemory(CpuInfo, 4 * sizeof(INT));
		__cpuid(CpuInfo, 0x80000008);
		MaxPhyAddr = CpuInfo[0] & 0x000000FF;
	}
	else
	{
		RtlZeroMemory(CpuInfo, 4 * sizeof(INT));
		__cpuid(CpuInfo, 0x01);
		if (CpuInfo[3] & 0x00020000)	// PSE-36 Support ?
		{
			MaxPhyAddr = 36;
		}
		else
		{
			MaxPhyAddr = 32;
		}
	}

	return MaxPhyAddr;
}