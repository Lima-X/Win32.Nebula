// NebulaBuilder - A commandline utility used to configure, patch/modify and build Nebula / the core
#include "bld.h"

// TODO: minor improvments and better error reporting (if im in the mood)
struct Opr {
	wchar* Comment;          // A string of the commandline from start til the OperatorTag

	u32    OperatorTag;      // The operator name (Tag), e.g. "/*rc*"
	struct Parameter {
		u32    ParameterTag; // The name of the Parameter (Tag), e.g. "-*fi*:"ply.dll""
		wchar* Argument;     // The argument string of the parameter, e.g. "-fi:*ply.dll*"
	}     *ParameterList;    // An array of Parameters
	u8     ParameterCount;   // The number of parameters that were parsed
	u32    Flags;            // a-z Flags, letter is taken as a offset relatve to 'a' in the ascii table
	                         // and is mapped onto the 32-Bit bitmap

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

		// Find beginning of the operation and parse comment/operator
		while (Iterator <= CommandLine + CmdlLength) {
			if (*Iterator == L'/') {
				// Parse Comment
				size_t CommentLength = (ptr)(Iterator - 1) - (ptr)CommandLine;
				Comment = (wchar*)HeapAlloc(Heap, 0, CommentLength + sizeof(*Comment));
				memcpy(Comment, CommandLine, CommentLength);
				Comment[CommentLength / sizeof(*Comment)] = L'\0';

				// Parse Tag
				auto TagEnd = FindDelimiter(++Iterator);
				size_t TagSize = (ptr)TagEnd - (ptr)Iterator;
				if (TagSize > 8) // Check that tag is not longer than 4 chars
					RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);
				for (auto i = 0; i < TagSize / 2; i++)
					((char*)&OperatorTag)[(3 - TagSize / 2) - i] = (char)Iterator[i];
				// memcpy((void*)&OperatorTag, Iterator, TagSize);
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
						ColonDelimiter == Iterator + 1 || // Colon follows parameter descriptor ("-:")
						ColonDelimiter + 1 == Delimiter)  // Colon is follows by non existent parameter ("-x: ...")
						RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);

					// Convert Tag and Argument to pair
					size_t TagSize = (ptr)ColonDelimiter - (ptr)Iterator;
					if (TagSize > 8) // Check that tag is not longer than 4 chars
						RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);
					auto& Tag = ParameterList[(ParameterCount - 1)].ParameterTag = 0;
					for (auto i = 0; i < TagSize / 2; i++)
						((char*)&Tag)[(3 - TagSize / 2) - i] = (char)Iterator[i];
					// memcpy(&Tag, Iterator, TagSize);
					Iterator = ColonDelimiter + 1;

					size_t ArgumentLength = (ptr)Delimiter - (ptr)Iterator;
					auto ParameterIndex = (ParameterCount - 1);
					auto& Argument = ParameterList[ParameterIndex].Argument;
					if (*Iterator == L'"')
						Iterator++, ArgumentLength -= 4;
					Argument = (wchar*)HeapAlloc(Heap, 0, ArgumentLength + 2);
					memcpy(Argument, Iterator, ArgumentLength);
					Argument[ArgumentLength / sizeof(wchar)] = L'\0';
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

i32 BuilderEntry() {
	SetUnhandledExceptionFilter([](_In_ EXCEPTION_POINTERS* ExceptionInfo) -> long {
			Con->PrintFEx(CON_ERROR, L"Unhandle exception occurred @ %#018llx !", ExceptionInfo->ExceptionRecord->ExceptionAddress);
			if (S_SUCCESS(CreateDump(nullptr, ExceptionInfo))) {
				Con->PrintFEx(CON_MESSAGE, L"Created minidumpfile in current directory.");
				ExitProcess(ExceptionInfo->ExceptionRecord->ExceptionCode);
			} else {
				Con->PrintFEx(CON_ERROR, L"Failed to dump process, halting process for debugger.");
				NtSuspendProcess(GetCurrentProcessId());
			}

			return EXCEPTION_CONTINUE_SEARCH;
		});

	Con = new Console;
	Opr* Op = nullptr;
	__try {
		Op = new Opr(GetCommandLineW());
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		delete Op;
		Con->PrintFEx(CON_ERROR, L"Invalid commandline syntax");
		return S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_COMMAND);
	}
	// Prolouge End

	switch (Op->OperatorTag) {
	case 0:
		break;

	case 'ps': // pack section
		{
			const wchar* FileName = nullptr;
			for (auto i = 0; i < Op->ParameterCount; i++)
				if (Op->ParameterList[i].ParameterTag = 'fi') {
					FileName = Op->ParameterList[i].Argument; break;
				}

			// Load executable
			FileMap Executable(FileName);
			auto PeStream = Executable.Data();
			auto NtHeader = utl::GetNtHeader(PeStream);

			// Get section information
			char SectionName[8] = { 0 };
			for (auto i = 0; i < Op->ParameterCount; i++)
				if (Op->ParameterList[i].ParameterTag = 'fi') {
					auto x = Op->ParameterList[i].Argument; break;
					auto y = wcslen(x);
					if (y > 8) // Check that the section name is not to long
						return S_CREATE(SS_ERROR, SF_BUILDER, SC_TOO_LONG);
					for (auto j = 0; j < y; j++) // Copy section name to ascii buffer
						SectionName[j] = (char)x[j];
					memset(SectionName + y, 0, 8 - y);
				}
			auto SectionHeader = utl::FindSection(NtHeader, SectionName);

			// Pack section
			if (CHECK_BMPFLAG(Op->Flags, 'p')) {

			}

			// Crypt section
			if (CHECK_BMPFLAG(Op->Flags, 'c')) {
				// Initialize RC4
				rc4 rc;
				u32 RtlState;

			#define KEY_SIZE 16
				byte RandomKey[KEY_SIZE];
				for (auto i = 0; i < KEY_SIZE / 4; i++)
					((u32*)RandomKey)[i] = RtlRandomEx(&RtlState);
				rc.ksa(RandomKey, KEY_SIZE);



			}

		} break;

	default:
		;
	}

	// Epiloge Start
	delete Op;
	delete Con;
	return SUCCESS;
}
