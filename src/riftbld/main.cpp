// NebulaBuilder - A commandline utility used to configure, patch/modify and build Nebula / the core
#include "bld.h"


struct Opr {
	wchar* Comment;          // A string of the commandline from start til the OperatorTag

	u64    OperatorTag;      // The operator name (Tag), e.g. "/*rc*"
	struct Parameter {
		u64    ParameterTag; // The name of the Parameter (Tag), e.g. "-*fi*:"ply.dll""
		wchar* Argument;     // The argument string of the parameter, e.g. "-fi:*ply.dll*"
	} *ParameterList;        // An array of Parameters
	u8     ParameterCount;   // The number of parameters that were parsed
	u32    Flags;            // a-z Flags, letter is taken as a offset relatve to 'a' in the ascii table
	                         // and is mapped onto the 32-Bit bitmap

	Opr(
		_In_z_ const wchar* CommandLine
	) {
		// Future proing for more extensive exceptionhandling
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
				memcpy((void*)&OperatorTag, Iterator, TagSize);
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
				if (ParameterList) {
					ParameterList = (Parameter*)HeapReAlloc(Heap, 0, ParameterList, ++ParameterCount * sizeof(Parameter));
				} else
					ParameterList = (Parameter*)HeapAlloc(Heap, 0, ++ParameterCount * sizeof(Parameter));

				// Find Colon Delimiter (Max at position 5 supported)
				const wchar* ColonDelimiter = nullptr;
				for (auto i = ++Iterator; i < Delimiter; i++)
					if (*i == L':') {
						ColonDelimiter = i;
						break;
					}

				if (ColonDelimiter) { // Parameter Argument Pair
					// Validate Parameter Integrity
					if (ColonDelimiter - Iterator > 4  || // Tag to big (tag longer than 4 chars)
						ColonDelimiter == Iterator + 1 || // Colon follows parameter descriptor ("-:")
						ColonDelimiter + 1 == Delimiter)  // Colon is follows by non existent parameter ("-x: ...")
						RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);

					// Convert Tag and Argument to pair
					size_t TagSize = (ptr)ColonDelimiter - (ptr)Iterator;
					if (TagSize > 8) // Check that tag is not longer than 4 chars
						RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);
					memcpy(&(ParameterList[(ParameterCount - 1)].ParameterTag = 0), Iterator, TagSize);
					Iterator = ColonDelimiter + 1;

					size_t ArgumentLength = (ptr)Delimiter - (ptr)Iterator;
					auto ParameterOffset = (ParameterCount - 1);
					ParameterList[ParameterOffset].Argument = (wchar*)HeapAlloc(Heap, 0, ArgumentLength + 2);
					memcpy(ParameterList[ParameterOffset].Argument, Iterator, ArgumentLength);
					ParameterList[ParameterOffset].Argument[ArgumentLength / sizeof(wchar)] = L'\0';
				} else // Flaglist
					while (Iterator < Delimiter)
						Flags |= 1 << (*Iterator++ - L'a');
			} else
				RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_DATA), 0, 0, nullptr);

			if (!*(Iterator = Delimiter)++) // Set Iterator to next location, incase its the end of the string exit
				break;
		}

	}
	~Opr() {
		auto Heap = GetProcessHeap();
		if (Comment)
			HeapFree(Heap, 0, (void*)Comment);
		if (ParameterList) {
			for (u8 i = 0; i < ParameterCount; i++)
				if (ParameterList[i].Argument)
					HeapFree(Heap, 0, (void*)ParameterList[i].Argument);
			HeapFree(Heap, 0, (void*)ParameterList);
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
				ObjectFlag ^= true;
			}

			SubString++;
		}

		if (!ObjectFlag)
			return SubString;
		return nullptr; // Invalid data
	}
};

i32 BuilderEntry() {
	Console Con;
	// Con.PrintFEx(L"FUCK YOU\n %s\nhi\nnew", 0,            L"asshole");

	Opr* Op = nullptr;
	__try {
		Op = new Opr(GetCommandLineW());
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		delete Op;
		Con.PrintFEx(L"Invalid commandline syntax", CON_ERROR);
		return EXCEPTION_CONTINUE_SEARCH;
	}

	switch (Op->OperatorTag) {
	case 0:

		break;

	default:
		;
	}

	delete Op;
	return SUCCESS;
}