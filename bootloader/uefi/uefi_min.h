/* Minimal x86_64 UEFI ABI used by the dependency-free BearBoot proof loader. */
#ifndef BBP_UEFI_MIN_H
#define BBP_UEFI_MIN_H

#include <stddef.h>
#include <stdint.h>

typedef uint64_t EFI_STATUS;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef size_t EFI_UINTN;
typedef void *EFI_HANDLE;
typedef uint16_t CHAR16;

#define EFIAPI __attribute__((ms_abi))

#define EFI_SUCCESS             UINT64_C(0)
#define EFI_LOAD_ERROR          UINT64_C(0x8000000000000001)
#define EFI_INVALID_PARAMETER   UINT64_C(0x8000000000000002)
#define EFI_BUFFER_TOO_SMALL    UINT64_C(0x8000000000000005)
#define EFI_OUT_OF_RESOURCES    UINT64_C(0x8000000000000009)
#define EFI_NOT_FOUND           UINT64_C(0x800000000000000e)

#define EFI_PAGE_SIZE 4096u
#define EFI_FILE_MODE_READ UINT64_C(1)

#define EFI_MEMORY_UC UINT64_C(0x0000000000000001)
#define EFI_MEMORY_WC UINT64_C(0x0000000000000002)
#define EFI_MEMORY_WT UINT64_C(0x0000000000000004)
#define EFI_MEMORY_WB UINT64_C(0x0000000000000008)
#define EFI_MEMORY_UCE UINT64_C(0x0000000000000010)
#define EFI_MEMORY_WP UINT64_C(0x0000000000001000)
#define EFI_MEMORY_RP UINT64_C(0x0000000000002000)
#define EFI_MEMORY_XP UINT64_C(0x0000000000004000)
#define EFI_MEMORY_RO UINT64_C(0x0000000000020000)

enum {
    AllocateAnyPages = 0,
    AllocateMaxAddress = 1,
    AllocateAddress = 2
};

enum {
    EfiReservedMemoryType = 0,
    EfiLoaderCode = 1,
    EfiLoaderData = 2,
    EfiBootServicesCode = 3,
    EfiBootServicesData = 4,
    EfiRuntimeServicesCode = 5,
    EfiRuntimeServicesData = 6,
    EfiConventionalMemory = 7,
    EfiUnusableMemory = 8,
    EfiACPIReclaimMemory = 9,
    EfiACPIMemoryNVS = 10,
    EfiMemoryMappedIO = 11,
    EfiMemoryMappedIOPortSpace = 12,
    EfiPalCode = 13,
    EfiPersistentMemory = 14
};

typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} EFI_GUID;

typedef struct {
    uint64_t Signature;
    uint32_t Revision;
    uint32_t HeaderSize;
    uint32_t CRC32;
    uint32_t Reserved;
} EFI_TABLE_HEADER;

typedef struct {
    uint32_t Type;
    uint32_t Pad;
    EFI_PHYSICAL_ADDRESS PhysicalStart;
    uint64_t VirtualStart;
    uint64_t NumberOfPages;
    uint64_t Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef EFI_STATUS (EFIAPI *EFI_ALLOCATE_PAGES)(uint32_t, uint32_t,
                                                EFI_UINTN,
                                                EFI_PHYSICAL_ADDRESS *);
typedef EFI_STATUS (EFIAPI *EFI_FREE_PAGES)(EFI_PHYSICAL_ADDRESS, EFI_UINTN);
typedef EFI_STATUS (EFIAPI *EFI_GET_MEMORY_MAP)(EFI_UINTN *,
                                                EFI_MEMORY_DESCRIPTOR *,
                                                EFI_UINTN *, EFI_UINTN *,
                                                uint32_t *);
typedef EFI_STATUS (EFIAPI *EFI_ALLOCATE_POOL)(uint32_t, EFI_UINTN, void **);
typedef EFI_STATUS (EFIAPI *EFI_FREE_POOL)(void *);
typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL)(EFI_HANDLE, EFI_GUID *, void **);
typedef EFI_STATUS (EFIAPI *EFI_EXIT_BOOT_SERVICES)(EFI_HANDLE, EFI_UINTN);

typedef struct EFI_BOOT_SERVICES {
    EFI_TABLE_HEADER Hdr;
    void *RaiseTPL;
    void *RestoreTPL;
    EFI_ALLOCATE_PAGES AllocatePages;
    EFI_FREE_PAGES FreePages;
    EFI_GET_MEMORY_MAP GetMemoryMap;
    EFI_ALLOCATE_POOL AllocatePool;
    EFI_FREE_POOL FreePool;
    void *CreateEvent;
    void *SetTimer;
    void *WaitForEvent;
    void *SignalEvent;
    void *CloseEvent;
    void *CheckEvent;
    void *InstallProtocolInterface;
    void *ReinstallProtocolInterface;
    void *UninstallProtocolInterface;
    EFI_HANDLE_PROTOCOL HandleProtocol;
    void *Reserved;
    void *RegisterProtocolNotify;
    void *LocateHandle;
    void *LocateDevicePath;
    void *InstallConfigurationTable;
    void *LoadImage;
    void *StartImage;
    void *Exit;
    void *UnloadImage;
    EFI_EXIT_BOOT_SERVICES ExitBootServices;
    void *GetNextMonotonicCount;
    void *Stall;
    void *SetWatchdogTimer;
    void *ConnectController;
    void *DisconnectController;
    void *OpenProtocol;
    void *CloseProtocol;
    void *OpenProtocolInformation;
    void *ProtocolsPerHandle;
    void *LocateHandleBuffer;
    void *LocateProtocol;
    void *InstallMultipleProtocolInterfaces;
    void *UninstallMultipleProtocolInterfaces;
    void *CalculateCrc32;
    void *CopyMem;
    void *SetMem;
    void *CreateEventEx;
} EFI_BOOT_SERVICES;

typedef struct EFI_SYSTEM_TABLE {
    EFI_TABLE_HEADER Hdr;
    CHAR16 *FirmwareVendor;
    uint32_t FirmwareRevision;
    uint32_t Pad;
    EFI_HANDLE ConsoleInHandle;
    void *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    void *ConOut;
    EFI_HANDLE StandardErrorHandle;
    void *StdErr;
    void *RuntimeServices;
    EFI_BOOT_SERVICES *BootServices;
    EFI_UINTN NumberOfTableEntries;
    void *ConfigurationTable;
} EFI_SYSTEM_TABLE;

typedef struct {
    uint32_t Revision;
    uint32_t Pad;
    EFI_HANDLE ParentHandle;
    EFI_SYSTEM_TABLE *SystemTable;
    EFI_HANDLE DeviceHandle;
    void *FilePath;
    void *Reserved;
    uint32_t LoadOptionsSize;
    uint32_t Pad2;
    void *LoadOptions;
    void *ImageBase;
    uint64_t ImageSize;
    uint32_t ImageCodeType;
    uint32_t ImageDataType;
    void *Unload;
} EFI_LOADED_IMAGE_PROTOCOL;

struct EFI_FILE_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_FILE_OPEN)(struct EFI_FILE_PROTOCOL *,
                                           struct EFI_FILE_PROTOCOL **,
                                           CHAR16 *, uint64_t, uint64_t);
typedef EFI_STATUS (EFIAPI *EFI_FILE_CLOSE)(struct EFI_FILE_PROTOCOL *);
typedef EFI_STATUS (EFIAPI *EFI_FILE_READ)(struct EFI_FILE_PROTOCOL *,
                                           EFI_UINTN *, void *);
typedef EFI_STATUS (EFIAPI *EFI_FILE_GET_INFO)(struct EFI_FILE_PROTOCOL *,
                                               EFI_GUID *, EFI_UINTN *, void *);

typedef struct EFI_FILE_PROTOCOL {
    uint64_t Revision;
    EFI_FILE_OPEN Open;
    EFI_FILE_CLOSE Close;
    void *Delete;
    EFI_FILE_READ Read;
    void *Write;
    void *GetPosition;
    void *SetPosition;
    EFI_FILE_GET_INFO GetInfo;
    void *SetInfo;
    void *Flush;
    void *OpenEx;
    void *ReadEx;
    void *WriteEx;
    void *FlushEx;
} EFI_FILE_PROTOCOL;

typedef struct {
    uint64_t Revision;
    EFI_STATUS (EFIAPI *OpenVolume)(void *, EFI_FILE_PROTOCOL **);
} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

typedef struct {
    uint64_t Size;
    uint64_t FileSize;
    uint64_t PhysicalSize;
} EFI_FILE_INFO_PREFIX;

static const EFI_GUID BBP_EFI_LOADED_IMAGE_GUID = {
    0x5b1b31a1u, 0x9562u, 0x11d2u,
    {0x8eu, 0x3fu, 0x00u, 0xa0u, 0xc9u, 0x69u, 0x72u, 0x3bu}
};
static const EFI_GUID BBP_EFI_SIMPLE_FILE_SYSTEM_GUID = {
    0x964e5b22u, 0x6459u, 0x11d2u,
    {0x8eu, 0x39u, 0x00u, 0xa0u, 0xc9u, 0x69u, 0x72u, 0x3bu}
};
static const EFI_GUID BBP_EFI_FILE_INFO_GUID = {
    0x09576e92u, 0x6d3fu, 0x11d2u,
    {0x8eu, 0x39u, 0x00u, 0xa0u, 0xc9u, 0x69u, 0x72u, 0x3bu}
};

_Static_assert(sizeof(EFI_MEMORY_DESCRIPTOR) == 40, "UEFI descriptor ABI");
_Static_assert(offsetof(EFI_BOOT_SERVICES, GetMemoryMap) == 56,
               "UEFI GetMemoryMap offset");
_Static_assert(offsetof(EFI_BOOT_SERVICES, ExitBootServices) == 232,
               "UEFI ExitBootServices offset");
_Static_assert(offsetof(EFI_SYSTEM_TABLE, BootServices) == 96,
               "UEFI system table ABI");

#endif
