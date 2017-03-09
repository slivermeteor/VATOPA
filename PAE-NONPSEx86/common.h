#ifndef CXX_COMMON_H
#define CXX_COMMON_H

#include <ntifs.h>
#include <math.h>	// 需要使用附加依赖库 libcntpr.lib

#define DEVICE_NAME L"\\Device\\PAENonPSEx86DeviceName"
#define LINK_NAME	L"\\DosDevices\\PAENonPSEx86LinkName"


VOID UnloadDriver(PDRIVER_OBJECT DriverObject);
NTSTATUS DefaultPassThrough(PDEVICE_OBJECT DeviceObject, PIRP pIrp);
NTSTATUS ControlPassThrough(PDEVICE_OBJECT DeviceObject, PIRP pIrp);

INT GetMaxPhysicalAddress();

#define CTL_PAE \
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_NEITHER, FILE_ANY_ACCESS)
#define CTL_IA32E \
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_NEITHER, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef union _VIRTUAL_ADDRESS_X86
{
	ULONG ulVirtualAddress;
	struct
	{
		union
		{
			struct
			{
				ULONG32 ul4KPageOffset : 12;
				ULONG32 PageTableIndex : 9;
			}Page4K;
			struct
			{
				ULONG32 ul2MPageOffset : 21;
			}Page2M;
		};

		ULONG32 PageDirTableIndex : 9;
		ULONG32 PageDirPointTableIndex : 2;
	}VirtualAddressForm;
}VIRTUAL_ADDRESS, *PVIRTUAL_ADDRESS;

typedef union _VIRTUAL_ADDRESSS_IA_32E
{
	ULONG64 ulVirtualAddress;
	struct
	{
		union
		{
			struct
			{
				union
				{
					struct
					{
						ULONG32 ul4KPageOffset : 12;
						ULONG32 PageTableEntryIndex : 9;
					}Page4K;
					struct
					{
						ULONG32 ul2MPageOffset : 21;
					}Page2M;
				};
				ULONG32 PageDirectoryEntryIndex : 9;
			}Page4K_2M;

			struct
			{
				ULONG32	ul1GPageOffset : 30;
			}Page1G;
		};

		ULONG32 PageDirPointTableEntryIndex : 9;
		ULONG32 PageMapLevel4EntryIndex : 9;
		ULONG32 ReserveSign : 16;

	}VirtualAddressForm;
}VIRTUAL_ADDRESS_IA_32E, *PVIRTUAL_ADDRESS_IA_32E;
#pragma pack(pop)

#endif	