#pragma once

#include <Windows.h>


typedef enum _SECTION_INHERIT : DWORD {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
	//PVOID UniqueProcess;
	//PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;



using NtOpenProcess = NTSTATUS(NTAPI*)(
	OUT PHANDLE             ProcessHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId
	);

using NtCreateSection = NTSTATUS(NTAPI*)(
	OUT PHANDLE   SectionHandle,
	IN ULONG DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PLARGE_INTEGER MaximumSize,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN OPTIONAL HANDLE FileHandle);


using NtMapViewOfSection = NTSTATUS(NTAPI*)(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
	IN OUT PSIZE_T ViewSize,
	IN DWORD InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect);

using NtUnmapViewOfSection = NTSTATUS(NTAPI*)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL
	);


using NtCreateThreadEx = NTSTATUS(NTAPI*)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
	);


#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}