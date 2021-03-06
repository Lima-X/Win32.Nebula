// NebulaBuilder - A commandline utility used to configure, patch/modify and build Nebula / the core
#include "bld.h"

// TODO: minor improvments and better error reporting (if im in the mood)
//       expand robustnest and maybe add support for nested operations
struct Opr {
#pragma region Structure
	wchar* Comment;          // A string of the commandline from start til the OperatorTag

	u32    OperatorTag;      // The operator name (Tag), e.g. "/*rc*"
	struct Parameter {
		u32    ParameterTag; // The name of the Parameter (Tag), e.g. "-*fi*:"ply.dll""
		wchar* Argument;     // The argument string of the parameter, e.g. "-fi:*ply.dll*"
	}     *ParameterList;    // An array of Parameters
	u16    ParameterCount;   // The number of parameters that were parsed a-z Flags,
	u32    Flags;            // letter is taken as a offset relatve to 'a' in the ascii table
	                         // and is mapped onto the 32-Bit bitmap
#pragma endregion

	Opr(                                // Initializes the commandline struct
		_In_z_ const wchar* CommandLine // the string to be used as the commandline
	) {
		// Future proving for more extensive exceptionhandling
		void* ExceptionParameterList[EXCEPTION_MAXIMUM_PARAMETERS];
		ExceptionParameterList[0] = this;
		memset(this, 0, sizeof(*this));

		auto Heap = GetProcessHeap();
		auto Iterator = CommandLine;
		auto CmdlLength = wcslen(CommandLine);

		// Get actual Commandline end
		while (Iterator[CmdlLength - 1] == ' ')
			CmdlLength--;

		// Find beginning of the operation and parse comment/operator
		while (Iterator <= CommandLine + CmdlLength) {
			if (*Iterator == L'/') {
				if (Iterator - CommandLine > 1) { // Parse comment if available
					size_t CommentLength = (ptr)(Iterator - 1) - (ptr)CommandLine;
					Comment = (wchar*)HeapAlloc(Heap, 0, CommentLength + sizeof(*Comment));
					memcpy(Comment, CommandLine, CommentLength);
					Comment[CommentLength / sizeof(*Comment)] = L'\0';
				}

				// Parse Tag
				auto TagEnd = FindDelimiter(++Iterator);
				size_t TagSize = ((ptr)TagEnd - (ptr)Iterator) / 2;
				if (TagSize > 4) // Check that tag is not longer than 4 chars
					RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);
				for (auto i = 0; i < TagSize; i++)
					((char*)&OperatorTag)[i] = (char)Iterator[TagSize - (i + 1)];
				Iterator = TagEnd + 1;
				break;
			}

			Iterator = FindDelimiter(Iterator) + 1;
			if (!Iterator)
				RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_POINTER), 0, 0, nullptr);
		}

		// Parse string until we hit the end of the string
		while (Iterator <= CommandLine + CmdlLength) {
			auto Delimiter = FindDelimiter(Iterator);

			if (*Iterator == L'-') {
				// Find Colon Delimiter (Max at position 5 supported (Tag size 4 chars))
				const wchar* ColonDelimiter = nullptr;
				for (auto i = ++Iterator; i < Delimiter; i++)
					if (*i == L':') {
						ColonDelimiter = i;
						break;
					}

				if (ColonDelimiter) { // Parameter Argument Pair
					if (ParameterList) {
						ParameterList = (Parameter*)HeapReAlloc(Heap, 0, ParameterList, ++ParameterCount * sizeof(Parameter));
					} else
						ParameterList = (Parameter*)HeapAlloc(Heap, 0, ++ParameterCount * sizeof(Parameter));

					// Validate Parameter Integrity
					if (ColonDelimiter - Iterator > 4  || // Tag to big (tag longer than 4 chars)
						ColonDelimiter == Iterator + 1)   // Colon follows parameter descriptor ("-:")
						RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);

					// Convert Tag and Argument to pair
					size_t TagSize = ((ptr)ColonDelimiter - (ptr)Iterator) / 2;
					if (TagSize > 4) // Check that tag is not longer than 4 chars
						RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);
					auto& Tag = ParameterList[(ParameterCount - 1)].ParameterTag = 0;
					for (auto i = 0; i < TagSize; i++)
						((char*)&Tag)[i] = (char)Iterator[TagSize - (i + 1)];;
					Iterator = ColonDelimiter + 1;

					auto ParameterIndex = (ParameterCount - 1);
					if (ColonDelimiter + 1 != Delimiter) {
						size_t ArgumentLength = (ptr)Delimiter - (ptr)Iterator;
						auto& Argument = ParameterList[ParameterIndex].Argument;
						if (*Iterator == L'"')
							Iterator++, ArgumentLength -= 4;
						Argument = (wchar*)HeapAlloc(Heap, 0, ArgumentLength + 2);
						memcpy(Argument, Iterator, ArgumentLength);
						Argument[ArgumentLength / sizeof(wchar)] = L'\0';
					} else // Colon is followed by non existent parameter ("-x: ...")
						ParameterList[ParameterIndex].Argument = nullptr;
				} else // Initialize flag list
					while (Iterator < Delimiter)
						Flags |= 1 << (*Iterator++ - L'a');
			} else
				RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);

			if (!*(Iterator = Delimiter)++) // Set Iterator to next location, incase its the end of the string exit
				break;
		}
	}
	~Opr() { // deconstructs the object
		auto m_Heap = GetProcessHeap();
		if (Comment)
			HeapFree(m_Heap, 0, (void*)Comment);
		if (ParameterList) {
			for (u8 i = 0; i < ParameterCount; i++)
				if (ParameterList[i].Argument)
					HeapFree(m_Heap, 0, (void*)ParameterList[i].Argument);
			HeapFree(m_Heap, 0, (void*)ParameterList);
		}
	}

	u16 GetTagIndex(
		_In_ u32 ParameterTag
	) {
		for (auto i = 0; i < ParameterCount; i++)
			if (ParameterList[i].ParameterTag == ParameterTag)
				return (u16)i;
		return (u16)-1;
	}

	const wchar* GetArgumentForTag(
		_In_ u32 ParameterTag
	) {
		const wchar* Argument = nullptr;
		for (auto i = 0; i < ParameterCount; i++)
			if (ParameterList[i].ParameterTag == ParameterTag) {
				Argument = ParameterList[i].Argument; break;
			}
		return Argument;
	}

private:
	const wchar* FindDelimiter(     // Searches for a commandline Delimiter
		_In_ const wchar* SubString // The starting point from whhere to search
	) {
		bool ObjectFlag = false;

		while (*SubString) {
			switch (*SubString) {
			case L' ':
				if (!ObjectFlag)
					return SubString;
				break;
			case L'"':
				ObjectFlag = !ObjectFlag;
			}

			SubString++;
		}

		if (!ObjectFlag)
			return SubString;
		return nullptr; // Invalid data
	}
};

#define HelpDialogue(Text) if (Op.GetTagIndex('help') != (u16)-1) {\
                              Con->PrintF(Text);\
                              return SUCCESS;\
                          }
status NebulaBuilder( // The actual builder code repsonsible for recompiling and building the image
	_In_ void* PeStream,
	_In_ Opr& Op
) {
	auto ProcessHeap = GetProcessHeap();

	switch (Op.OperatorTag) {
	case 'ps': // pack section
		{
			HelpDialogue(L"Packs a section in the physical image:\n")

			auto NtHeader = utl::GetNtHeader(PeStream);

			// Get section information
			Con->PrintFEx(CON_INFO, L"Retrieving section information");
			char SectionName[8] = { 0 };
			{
				auto SectionParameter = Op.GetArgumentForTag('sec');
				auto y = wcslen(SectionParameter);
				if (y > 8) // Check that the section name is not to long
					return S_CREATE(SS_ERROR, SF_BUILDER, SC_TOO_LONG);
				for (auto j = 0; j < y; j++) // Copy section name to ascii buffer
					SectionName[j] = (char)SectionParameter[j];
				memset(SectionName + y, 0, 8 - y);
			}
			auto SectionHeader = utl::FindSection(NtHeader, SectionName);

			// Pack section
			if (CHECK_BMPFLAG(Op.Flags, 'p')) {

			}

			// Crypt section
			if (CHECK_BMPFLAG(Op.Flags, 'c')) {
				// Initialize RC4
				u32 RtlState;

			#define KEY_SIZE 16
				byte RandomKey[KEY_SIZE];
				for (auto i = 0; i < KEY_SIZE / 4; i++)
					((u32*)RandomKey)[i] = RtlRandomEx(&RtlState);



			}

		} break;

	case 'ree': // remove export entry
		{
			HelpDialogue(L"Removes an export entry from the export section,\n"
				L"All links to the Data are purged form the image, the data is left intact."
				L"\"fi\" : Executable to modify\n"
				L"\"en\" : ExportName to be destroyed\n"
				L"    This can be a direct name or an ordinal designated by an '@'\n"
				L"    e.g. -en:NbConfig or -en:@13 (ordinals are unbiased)\n"
				L"    BY ORDINAL IS CURRENTLY NOT FULLY SUPPORTED, ONLY REMOVES ADDRESS ENTRY!")

			// Get ExportDirectory
			auto NtHeader = utl::GetNtHeader(PeStream);
			auto ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((ptr)img::TranslateRvaToPa(PeStream,
				NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) + (ptr)PeStream);
			Con->PrintFEx(CON_INFO, L"ExportDirectory at 0x%08x", (ptr)ExportDirectory - (ptr)PeStream);

			auto ExportName = Op.GetArgumentForTag('en');
			if (!ExportName)
				return S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_POINTER);
			auto Ordinal = (u16)-1; // Set to invalid ordinal by default

			if (*ExportName != L'@') { // Find ordinal of export
				// Enumerate ExportNameTable and find matching entry
				auto ExportNameTable = (u32*)((ptr)img::TranslateRvaToPa(PeStream, ExportDirectory->AddressOfNames) + (ptr)PeStream);
				Con->PrintFEx(CON_INFO, L"ExportNameTable at 0x%08x", (ptr)ExportNameTable - (ptr)PeStream);

				// Convert Unicode to ascii string
				auto ExportNameLength = wcslen(ExportName);
				auto AnsiExportName = (char*)HeapAlloc(ProcessHeap, 0, ExportNameLength + 1);
				WideCharToMultiByte(CP_ACP, 0, ExportName, -1, AnsiExportName, ExportNameLength + 1, 0, 0);

				// Find exportname
				for (auto i = 0; i < ExportDirectory->NumberOfNames; i++) {
					auto ExportedName = (char*)((ptr)img::TranslateRvaToPa(PeStream, ExportNameTable[i]) + (ptr)PeStream);

					if (!strcmp(ExportedName, AnsiExportName)) {
						Con->PrintFEx(CON_INFO, L"Exported name found at 0x%08x", (ptr)ExportedName - (ptr)PeStream);
						auto ExportOrdinalTable = (u16*)((ptr)img::TranslateRvaToPa(
							PeStream, ExportDirectory->AddressOfNameOrdinals) + (ptr)PeStream);
						Con->PrintFEx(CON_INFO, L"ExportOrdinalTable at 0x%08x", (ptr)ExportOrdinalTable - (ptr)PeStream);

						// Remove ordinal and namerva from tables, destroy string
						Ordinal = ExportOrdinalTable[i];
						memmove(ExportNameTable + i, ExportNameTable + (i + 1),
							(ExportDirectory->NumberOfNames - (i + 1)) * sizeof(u32));
						ExportNameTable[i + 1] = null;
						memmove(ExportOrdinalTable + i, ExportOrdinalTable + (i + 1),
							(ExportDirectory->NumberOfNames - (i + 1)) * sizeof(u16));
						ExportOrdinalTable[i + 1] = null;
						memset(ExportedName, null, ExportNameLength);

						ExportDirectory->NumberOfNames--;
						Con->PrintFEx(CON_SUCCESS, L"Destroyed name and fixed up tables");
						break;
					}
				}

				HeapFree(ProcessHeap, 0, AnsiExportName);
			} else // directly use ordinal
				Ordinal = (u16)_wtoi(ExportName + 1);

			if (Ordinal != (u16)-1) {
				if (Ordinal > ExportDirectory->NumberOfFunctions) {
					Con->PrintFEx(CON_ERROR, L"Ordinal outside of ExportAddressTable: @%d", Ordinal);
					return S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_PARAMETER);
				}

				// Remove export rva from eat
				auto ExportAddressTable = (u32*)((ptr)img::TranslateRvaToPa(PeStream,
					ExportDirectory->AddressOfFunctions) + (ptr)PeStream);
				Con->PrintFEx(CON_INFO, L"ExportAddressTable at 0x%08x", (ptr)ExportAddressTable - (ptr)PeStream);

				// IMPROVEMENT: not only destroy the entry but compress the table and relink the ordinals in the ordinal table
				ExportAddressTable[Ordinal] = null;
				Con->PrintFEx(CON_SUCCESS, L"Removed Export @%d, at 0x%08x", Ordinal, (ptr)(ExportAddressTable + Ordinal) - (ptr)PeStream);
			} else
				Con->PrintFEx(CON_WARNING, L"Export not found");
		} break;

	case 'spp': // section page protection
		{
			HelpDialogue(L"Sets the section characteristics of the spefied section\n"
				L"\"fi\" : the executable to patch\n"
				L"\"sc\" : teh sectionname of the header to patch\n"
				L"\"ch\" : the protection / characteristics to use in hex")

			auto NtHeader = utl::GetNtHeader(PeStream);

			// Get Argument
			auto SectionName = Op.GetArgumentForTag('sc');
			auto SectionNameLength = wcslen(SectionName);
			if (SectionNameLength > 8) {
				Con->PrintFEx(CON_ERROR, L"Section name specified invalid");
				return S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_PARAMETER);
			}

			// Find Section
			char SectionNameBuffer[8];
			for (auto i = 0; i < SectionNameLength; i++)
				SectionNameBuffer[i] = (char)SectionName[i];
			memset(SectionNameBuffer + SectionNameLength, 0, 8 - SectionNameLength);
			auto SectionHeader = utl::FindSection(NtHeader, SectionNameBuffer);
			if (!SectionHeader) {
				Con->PrintFEx(CON_ERROR, L"Could not retrieve section");
				return S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_POINTER);
			}
			Con->PrintFEx(CON_INFO, L"Sectionheader located at 0x%08x", (ptr)SectionHeader - (ptr)PeStream);

			auto Protection = Op.GetArgumentForTag('ch');
			u32 ProtectionVar;
			if (swscanf_s(Protection, L"%lx", &ProtectionVar) != 1) {
				Con->PrintFEx(CON_ERROR, L"Invalid characteristic !");
				return S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_PARAMETER);
			}
			SectionHeader->Characteristics = ProtectionVar;
			Con->PrintFEx(CON_SUCCESS, L"Sectioncharacteristics set at location 0x%08x",
				(ptr)&SectionHeader->Characteristics - (ptr)PeStream);
		} break;

	case 'ccsc': // code cipher shellcode
		{
			HelpDialogue(L"encodes the shellcode rc4 cipher used for the .nb2 section\n"
				L"\"fi\" : the executable used for the ciphering")

			auto TargetFile = Op.GetArgumentForTag('fi');

			// Get xor code key location and set key
			u64* XorKey;
			auto Status = img::GetExportImageAddress(PeStream, "NbRc4ModShellCodeKey", (void*&)XorKey);
			if (!S_SUCCESS(Status))
				return Status;
			u32 RtlState;
			*XorKey = (u64)RtlRandomEx(&RtlState) << 32 | RtlRandomEx(&RtlState);
			Con->PrintFEx(CON_INFO, L"NbRc4ModShellCodeKey at 0x%08x set to 0x%016llx", (ptr)XorKey - (ptr)PeStream, *XorKey);

			// Remove ShellCodeKey export
			Status = RunChildService(PeStream, L"/ree -fi:%s -en:%s", TargetFile, L"NbRc4ModShellCodeKey");
			if (!S_SUCCESS(Status))
				return Status;

			// Get cipher shellcode location and xor encode
			u8* rc4modsc;
			Status = img::GetExportImageAddress(PeStream, "NbRc4ModShellCode", (void*&)rc4modsc);
			if (!S_SUCCESS(Status))
				return Status;
			Con->PrintFEx(CON_INFO, L"Ciphering Rc4ModShellCode at 0x%08x", (ptr)rc4modsc - (ptr)PeStream);
			for (auto i = 0; i < 0x1d4; i++)
				rc4modsc[i] = _rotr8(rc4modsc[i] ^ ((u8*)XorKey)[i & 0x7], i & 0x3);

			// Remove ShellCode export
			Status = RunChildService(PeStream, L"/ree -fi:%s -en:%s", TargetFile, L"NbRc4ModShellCode");
			if (!S_SUCCESS(Status))
				return Status;
			Con->PrintFEx(CON_SUCCESS, L"Successfully crypted shellcode and removed entries.");
		} break;

	default:
		Con->PrintF(L"Unrecognized Command/Operation\n"
			L"A List of known operations is provided below,\n"
			L"for a better descriptions of each operation use the \"-help:\" tag");
	}

	return SUCCESS;
}
#undef HelpDialogue

status RunChildService(                // Runs a sub service Builder instance
	_In_           void*  Buffer,      // The buffer to work on
	_In_z_   const wchar* CommandLine, // Commandline template used for the builder
	_In_opt_                      ...  // arguments used for commandline template
) {
	Con->m_BaseIndent += 4;

	// Create commandline from template
	auto CommandLineBuffer = (wchar*)VirtualAlloc(nullptr, PAGE_SIZE, MEM_ALLOC, PAGE_READWRITE);
	va_list VariableArgumentList;
	va_start(VariableArgumentList, CommandLine);
	vswprintf_s(CommandLineBuffer, PAGE_SIZE / sizeof(wchar), CommandLine, VariableArgumentList);
	va_end(VariableArgumentList);

	// Create Commandline and run Builder
	Opr Op(CommandLineBuffer);
	auto Status = NebulaBuilder(Buffer, Op);

	VirtualFree(CommandLineBuffer, 0, MEM_RELEASE);

	Con->m_BaseIndent -= 4;
	return Status;
}

// This Entrypoint needs some serious rework :flushed:
i32 BuilderEntry() {
	SetUnhandledExceptionFilter([](_In_ EXCEPTION_POINTERS* ExceptionInfo) -> long {
			Con->PrintFEx(CON_ERROR, L"Unhandle exception occurred @ 0x%016llx !", ExceptionInfo->ExceptionRecord->ExceptionAddress);
			if (S_SUCCESS(DbgCreateDump(nullptr, ExceptionInfo))) {
				Con->PrintFEx(CON_WARNING, L"Created minidumpfile in current directory.");
				ExitProcess(ExceptionInfo->ExceptionRecord->ExceptionCode);
			} else {
				Con->PrintFEx(CON_ERROR, L"Failed to dump process, halting process for debugger.");
				NtSuspendProcess(GetCurrentProcessId());
			}

			return EXCEPTION_CONTINUE_SEARCH;
		});
	Con = new Console;

	// Create Commandline
	Opr* Op = nullptr;
	__try {
		Op = new Opr(GetCommandLineW());
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		delete Op;
		Con->PrintFEx(CON_ERROR, L"Invalid commandline syntax");
		return S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_COMMAND);
	}
	// Prolouge End


	// Load executable
	auto TargetFile = Op->GetArgumentForTag('fi');
	void* PeStream = nullptr;

	FileMap* File = nullptr;
	if (TargetFile) {
		File = new FileMap(TargetFile);
		PeStream = File->Data();
		if (!PeStream)
			return S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_POINTER);
		Con->PrintFEx(CON_INFO, L"Loaded executable");
	}

	auto Status = NebulaBuilder(PeStream, *Op);
	if (!S_SUCCESS(Status))
		Con->PrintFEx(CON_ERROR, L"Last status code: 0x%08x", Status);
	delete File;

	// Epiloge Start
	delete Op;
	delete Con;
	return Status;
}
