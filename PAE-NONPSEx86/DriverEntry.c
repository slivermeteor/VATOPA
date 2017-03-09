#ifndef CXX_COMMON_H
#	include "common.h"
#endif

// ������������Ҫ /SAFESEH:NO 
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
	case CTL_PAE:	// PAE ��ʵҲӦ����8�ֽڵĳ�1�������� - �д�����
	{
		VirtualAddress.ulVirtualAddress = *((PULONG)InputBuffer);
		DbgPrint("����������ַ:0x%p\r\n", VirtualAddress.ulVirtualAddress);
		// �õ�MaxPhysicalAddress- 64λ�µ�PAE��Ҫ�õ� 32λ�µ�PAE������Ҫ
		ulMaxPhysicalAddressBit = GetMaxPhysicalAddress();
		for (i = 12; i < ulMaxPhysicalAddressBit; i++)
		{
			ulMaxPhysicalAddress += pow(2, i);
		}
		DbgPrint("��ǰϵͳ��������ַ%dλ,����ɵ���ֵ:%llx", ulMaxPhysicalAddressBit, ulMaxPhysicalAddress);

		// �����MDL ��VirtualAddress������ - ������Ҫ
		//pVirtualAddressMDL = IoAllocateMdl((PVOID)(VirtualAddress.ulVirtualAddress), ulInputBufferLength, FALSE, FALSE, NULL);
		//MmBuildMdlForNonPagedPool(pVirtualAddressMDL);
		
		// �ظ�����
		// 1.��һ������CR3�еõ���������ַ
		// 2.�õ�����
		// 3.���������Ҫ�ҵı���������ַ
		// 4.ӳ�������ַ - ���ʵõ���һ������������ַ 
		// 5.�ص���һ��
		// ֱ���õ�ҳ���׵�ַ��ֱ�Ӽ�ƫ�� ӳ�� ���� �õ�ֵ

		// PDPT -> PDT 2λindex	
		PageDirPointTableBasePA = __readcr3();							// 1 �õ�CR3��ֵ
		PageDirPointTableBasePA = PageDirPointTableBasePA & 0xFFFFFFE0;	// ȥ������λ

		PageDirPointTableEntryIndex = VirtualAddress.VirtualAddressForm.PageDirPointTableIndex;		// 2 ȡ�� PDPT ����
		// ʵ��ȥӳ��ĵ�ַ Ӧ����������ĵ�ַ ����Ӧ�üӺ�ƫ����ȥӳ��
		PhysicalAddress.LowPart = PageDirPointTableBasePA + 8 * PageDirPointTableEntryIndex;			// 3
		// CR3�������ַ - ������Ҫ����ֻ����һ�������ַӳ�䵽�� ͨ��������������ַ������
		pPageDirPointTableEntryVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);	// 4
		DbgPrint("CR3(PageDirPointTableBase)\t�����ַ:0x%p\t���������:%d\t����������ַ:0x%p\t��������ӳ���ַ:0x%p\r\n", 
				 PageDirPointTableBasePA, PageDirPointTableEntryIndex, PageDirPointTableBasePA + 8 * PageDirPointTableEntryIndex, pPageDirPointTableEntryVA);
		
		PageDirTableBasePA = *pPageDirPointTableEntryVA & 0xFFFFF000;	     // 5. ���ʵõ���һ������������ַ��Ĩ�������λ,PDPT�е�ÿ��������һ��PDT�Ļ���ַ
		
		// PDT -> PT	9λ����
		PageDirEntryIndex = VirtualAddress.VirtualAddressForm.PageDirTableIndex;		// 2 ȡ��PDT����
		PhysicalAddress.LowPart = PageDirTableBasePA + 8 * PageDirEntryIndex;			// 3
		pPageDirEntryVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);		// 4
		DbgPrint("PageDirectoryTableBase\t�����ַ:0x%p\t���������:%d\t����������ַ:0x%p\t����ӳ���ַ:0x%p\r\n", 
			     PageDirTableBasePA, PageDirEntryIndex, PageDirTableBasePA + 8 * PageDirEntryIndex, pPageDirEntryVA);
		// 4K - 2M ҳ��ֱ��� �ж� PDE.PS([7])
		if (*pPageDirEntryVA & 0x00000080)
		{
			DbgPrint("��ǰҳ�����2Mҳ��ӳ�䷽ʽ\r\n");
			PageBasePA = *pPageDirEntryVA & 0xFFE00000;	// [MAXPHYSICAL:21] PDE ֱ��ȡ�� PageBase
			ulPhysicalAddressPA = PageBasePA + VirtualAddress.VirtualAddressForm.Page2M.ul2MPageOffset;	// ��ƫ��
			PhysicalAddress.LowPart = ulPhysicalAddressPA;
			pPhysicalAddressVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);

			DbgPrint("PageBase\t�����ַ:0x%p\tҳƫ��:0x%p\t���������ַ:0x%p\tӳ�������ַ:0x%p\t��ַ��ֵ:%s\r\n",
				PageBasePA, VirtualAddress.VirtualAddressForm.Page2M.ul2MPageOffset, ulPhysicalAddressPA, pPhysicalAddressVA, pPhysicalAddressVA);

			*((PULONG)OutputBuffer) = ulPhysicalAddressPA;
		}
		else
		{
			DbgPrint("��ǰҳ�����4Kҳ��ӳ�䷽ʽ\r\n");
			PageTableBasePA = *pPageDirEntryVA & 0xFFFFF000;			// 5 ���ʵõ���һ������������ַ��Ĩ���������λ,PDT��ÿ��������һ��PD�Ļ���ַ
																			
			PageTableEntryIndex = VirtualAddress.VirtualAddressForm.Page4K.PageTableIndex;	// PT -> Page  9λ����
			PhysicalAddress.LowPart = PageTableBasePA + 8 * PageTableEntryIndex;
			pPageTableEntryVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
			DbgPrint("PageTableBase\t�����ַ:0x%p\t���������:%x\t����������ַ:0x%p\t����ӳ���ַ:0x%p\r\n",
				PageTableBasePA, PageTableEntryIndex, PageTableBasePA + 8 * PageTableEntryIndex, pPageTableEntryVA);

			PageBasePA = *pPageTableEntryVA & 0xFFFFF000;

			// ������ҳ��ƫ�� 12λƫ��
			ulPhysicalAddressPA = PageBasePA + VirtualAddress.VirtualAddressForm.Page4K.ul4KPageOffset;
			PhysicalAddress.LowPart = ulPhysicalAddressPA;
			pPhysicalAddressVA = (PULONG)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);

			DbgPrint("PageBase\t�����ַ:0x%p\tҳƫ��:0x%p\t���������ַ:0x%p\tӳ�������ַ:0x%p\t��ַ��ֵ:%s\r\n",
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
		DbgPrint("����������ַ:%llx\r\n", VirtualAddress.ulVirtualAddress);
		// �õ� MaxPhysicalAddress
		ulMaxPhysicalAddressBit = GetMaxPhysicalAddress();
		for (i = 12; i < ulMaxPhysicalAddressBit; i++)
		{
			ulMaxPhysicalAddress += pow(2, i);
		}
		DbgPrint("��ǰϵͳ��������ַ%dλ,����ɵ���ֵ:%llx", ulMaxPhysicalAddressBit, ulMaxPhysicalAddress);

		// 1.�õ�����ַ
		// 2.������ֵ�������õ�������ַ
		// 3.�������ַ�еõ�����
		// 4.�õ�Ҫ�ҵı���������ַ
		// 5.ӳ�������ַ - �õ�ӳ�������ַ -> ���ʵõ���һ����Ļ���ַ �ص�1
		// ֱ���õ�ҳ�����ַ + ҳ��ƫ�� �͵õ�ʵ�ʵ�ַ ��ӳ��һ�� ���ʼ���

		// CR3 -> PML4T Base -> PML4E -> PDPT Base
		PageMapLevel4TableBasePA = __readcr3();					// 1.ȡ����ַ
		PageMapLevel4TableBasePA &= ulMaxPhysicalAddress;		// 2.�� MaxPhyAddr�� ȥ��ͷ��
		PageMapLevel4TableBasePA &= 0xFFFFFFFFFFFFF000;			// 2.ȥ������λ      4K����
		PageMapLevel4EntryIndex = VirtualAddressIA32E.VirtualAddressForm.PageMapLevel4EntryIndex;	// 3.�õ�����
		PhysicalAddress.QuadPart = PageMapLevel4TableBasePA + 8 * PageMapLevel4EntryIndex;			// 4.�õ����������ַ
		pPageMapLevel4EntryVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);	// 5.����ӳ��
		DbgPrint("CR3(PageMapLevel4TableBase)\t�����ַ:%#llx\t���������:%d\t����������ַ:%#llx\t��������ӳ���ַ:%#llx\r\n",
			PageMapLevel4TableBasePA, PageMapLevel4EntryIndex, PageMapLevel4TableBasePA + 8 * PageMapLevel4EntryIndex, pPageMapLevel4EntryVA);

		// PDPT Base -> PDPTE    -> PDT Base / 1G Page Base
		PageDirPointTableBasePA = *pPageMapLevel4EntryVA;		// ������һ������ �õ���һ����Ļ���ַ
		PageDirPointTableBasePA &= ulMaxPhysicalAddress;
		PageDirPointTableBasePA &= 0xFFFFFFFFFFFFF000;
		PageDirPointTableEntryIndex = VirtualAddressIA32E.VirtualAddressForm.PageDirPointTableEntryIndex;
		PhysicalAddress.QuadPart = PageDirPointTableBasePA + 8 * PageDirPointTableEntryIndex;
		pPageDirPointTableEntryVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
		DbgPrint("PageDirPointTableBase\t�����ַ:%#llx\t���������:%d\t����������ַ:%#llx\t��������ӳ���ַ:%#llx\r\n",
			PageDirPointTableBasePA, PageDirPointTableEntryIndex, PageDirPointTableBasePA + 8 * PageDirPointTableEntryIndex, pPageDirPointTableEntryVA);
		
		PageDirTableBasePA = *pPageDirPointTableEntryVA;	
		if (PageDirTableBasePA & 0x0000000000000080)		// �ж�PDPTE����λ �ж��Ƿ��� 1Gҳ��ӳ�䷽ʽ
		{
			DbgPrint("��ǰҳ�����1Gҳ��ӳ�䷽ʽ\r\n");
			// PDPTE -> 1G Page Base + Offset
			PageBasePA = PageDirTableBasePA & ulMaxPhysicalAddress;	// PageDirTableBasePA �Ѿ���δ������� Page Baseֵ����Ϊ����PDPTE�����ֵ����ֱ�����������������ȥͷ������
			PageBasePA &= 0xFFFFFFFF30000000;
			ulPhysicalAddressPA = PageBasePA + VirtualAddressIA32E.VirtualAddressForm.Page1G.ul1GPageOffset;
			pPhysicalAddressVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
			DbgPrint("PageBase\t�����ַ:%#llx\tҳƫ��:0x%x\t���������ַ:%#llx\tӳ�������ַ:%#llx\t��ַ��ֵ:%s\r\n",
				PageBasePA, VirtualAddressIA32E.VirtualAddressForm.Page1G.ul1GPageOffset, ulPhysicalAddressPA, pPhysicalAddressVA, pPhysicalAddressVA);
		}
		// 4K / 2M ҳ��ӳ�䷽ʽ -> �����õ�PDT Base
		else
		{
			// PDT Base -> PDE		-> PT Base / 2M Page Base
			PageDirTableBasePA &= ulMaxPhysicalAddress;
			PageDirTableBasePA &= 0xFFFFFFFFFFFFF000;
			PageDirEntryIndex = VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.PageDirectoryEntryIndex;
			PhysicalAddress.QuadPart = PageDirPointTableBasePA + 8 * PageDirEntryIndex;
			pPageDirEntryVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
			DbgPrint("PageDirectoryTableBase\t�����ַ:%#llx\t���������:%d\t����������ַ:%#llx\t����ӳ���ַ:%#llx\r\n",
				PageDirTableBasePA, PageDirEntryIndex, PageDirTableBasePA + 8 * PageDirEntryIndex, pPageDirEntryVA);

			PageTableBasePA = *pPageDirEntryVA;
			if (PageTableBasePA & 0x0000000000000080)	// �ж�PDE����λ �ж��Ƿ��� 2Mҳ��ӳ�䷽ʽ
			{
				DbgPrint("��ǰҳ�����2Mҳ��ӳ�䷽ʽ\r\n");
				// PDE -> 2M Page Base + Offset
				PageBasePA = PageTableBasePA & ulMaxPhysicalAddress;	// PageTableBasePA �Ѿ���δ�������Baseֵ��������͵��ֱ��������ʼ���е�һ������Ȼ����и�ֵ
				PageBasePA &= 0xFFFFFFFFFFE00000;
				ulPhysicalAddressPA = PageBasePA + VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.Page2M.ul2MPageOffset;
				pPhysicalAddressVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
				DbgPrint("PageBase\t�����ַ:%#llx\tҳƫ��:0x%x\t���������ַ:%#llx\tӳ�������ַ:%#llx\t��ַ��ֵ:%s\r\n",
					PageBasePA, VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.Page2M.ul2MPageOffset, ulPhysicalAddressPA, pPhysicalAddressVA, pPhysicalAddressVA);
			}
			// 4K ҳ��ӳ�䷽ʽ -> �����õ�PT Base
			else
			{
				DbgPrint("��ǰҳ�����4Kҳ��ӳ�䷽ʽ\r\n");
				// PT -> PTE -> 4K Page Base
				PageTableBasePA &= ulMaxPhysicalAddress;
				PageTableBasePA &= 0xFFFFFFFFFFFFF000;
				PageTableEntryIndex = VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.Page4K.PageTableEntryIndex;
				PhysicalAddress.QuadPart = PageTableBasePA + 8 * PageTableEntryIndex;
				pPageTableEntryVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
				DbgPrint("PageTableBase\t�����ַ:%#llx\t���������:%x\t����������ַ:%#llx\t����ӳ���ַ:%#llx\r\n",
					PageTableBasePA, PageTableEntryIndex, PageTableBasePA + 8 * PageTableEntryIndex, pPageTableEntryVA);

				// 4K Page Base + Offset
				PageBasePA = *pPageTableEntryVA;
				PageBasePA &= 0xFFFFFFFFFFFFF000;
				PageBasePA &= ulMaxPhysicalAddress;
				ulPhysicalAddressPA = PageBasePA + VirtualAddressIA32E.VirtualAddressForm.Page4K_2M.Page4K.ul4KPageOffset;
				PhysicalAddress.QuadPart = ulPhysicalAddressPA;
				pPhysicalAddressVA = (PULONG64)MmMapIoSpace(PhysicalAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);
				DbgPrint("PageBase\t�����ַ:%#llx\tҳƫ��:0x%x\t���������ַ:%#llx\tӳ�������ַ:%#llx\t��ַ��ֵ:%s\r\n",
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

// �õ�֧����������ַ֧��
INT GetMaxPhysicalAddress()
{
	INT CpuInfo[4] = { 0 };
	ULONG32 MaxPhyAddr = 0;
	__cpuidex(CpuInfo, 0x80000000, 32);
	if (CpuInfo[0] == 0x80000008)		// ֧�� 0x80000008 ��ѯ��?
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