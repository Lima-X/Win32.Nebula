// IO Controller - Manages File And Console IO
#include "bld.h"

#pragma region Console
u32    Console::m_nRefCounter;

Console::Console(
	_In_ dword ProcessId
) {
	m_csbiBackup.cbSize = sizeof(m_csbiBackup);
	GetConsoleScreenBufferInfoEx(m_ConsoleOutput, &m_csbiBackup);

	m_ConsoleInput  = GetStdHandle(STD_INPUT_HANDLE);
	m_ConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	if (!(_InterlockedIncrement(&m_nRefCounter) - 1)) {
	#if 0 // Attach to existing console or create (not used here as the subsystem does this for us)
		if (!ProcessId)
			ProcessId = GetCurrentProcessId();
		if (!AttachConsole(ProcessId))
			if (!AllocConsole())
				RaiseException(S_CREATE(SS_ERROR, SF_BUILDER, SC_COULDNT_ATTACH), 0, 0, nullptr);
	#endif

		m_Buffer = VirtualAlloc(nullptr, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	}
}
Console::~Console() {
	if (!_InterlockedDecrement(&m_nRefCounter))
		VirtualFree(m_Buffer, 0, MEM_RELEASE);
	SetConsoleScreenBufferInfoEx(m_ConsoleOutput, &m_csbiBackup);
}

status Console::Cls() {
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	status s = SUCCESS;

	s= !GetConsoleScreenBufferInfo(m_ConsoleOutput, &csbi);
	dword dw;
	s = !FillConsoleOutputCharacterW(m_ConsoleOutput, 0, csbi.dwSize.X * csbi.dwSize.Y, { 0, 0 }, &dw);
	s = !GetConsoleScreenBufferInfo(m_ConsoleOutput, &csbi);
	s = !FillConsoleOutputAttribute(m_ConsoleOutput, csbi.wAttributes, csbi.dwSize.X * csbi.dwSize.Y, { 0, 0 }, &dw);
	s = !SetConsoleCursorPosition(m_ConsoleOutput, { 0, 0 });

	return s ? S_CREATE(SS_WARNING, SF_NULL, SC_INCOMPLETE) : s;
}

status Console::vPrintFormatW(_In_z_ const wchar* Text, _In_opt_ va_list Va) {
	// Format Message
	vswprintf_s((wchar*)m_Buffer, 0x1000, Text, Va);
	m_BufferSize = wcslen((wchar*)m_Buffer) * sizeof(wchar);

	// Print Message
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(m_ConsoleOutput, &csbi);
	word Attributes = csbi.wAttributes & 0xfff0;
		Attributes |= m_ErrorLevel & 0xf;
	SetConsoleTextAttribute(m_ConsoleOutput, Attributes);

	SetConsoleCursorPosition(m_ConsoleOutput, { 0, csbi.dwCursorPosition.Y });
	wchar Symbol[] = L"[ ] ";
	switch (m_ErrorLevel) {
	case CON_SUCCESS:  Symbol[1] = L'S'; break;
	case CON_MESSAGE:  Symbol[1] = L'+'; break;
	case CON_QUESTION: Symbol[1] = L'?'; break;
	case CON_WARNING:  Symbol[1] = L'!'; break;
	case CON_ERROR:    Symbol[1] = L'X'; break;
	}
	dword v0;
	WriteConsoleW(m_ConsoleOutput, Symbol, 4, &v0, nullptr);

	auto BufferOffset = (const wchar*)m_Buffer;
	i16 linecounter = 1;
	while (m_BufferSize) {
		const wchar* Delimiter = wcschr((wchar*)BufferOffset, L'\n');
		if (Delimiter) {
			WriteConsoleW(m_ConsoleOutput, BufferOffset, (u32)(Delimiter - BufferOffset), &v0, nullptr);
			m_BufferSize -= (ptr)Delimiter - (ptr)BufferOffset + 2;
			BufferOffset = Delimiter + 1;
			SetConsoleCursorPosition(m_ConsoleOutput, { 4, csbi.dwCursorPosition.Y + linecounter });
			linecounter++;
		} else {
			WriteConsoleW(m_ConsoleOutput, BufferOffset, m_BufferSize / sizeof(wchar), &v0, nullptr);
			m_BufferSize = 0;
		}
	}

	SetConsoleCursorPosition(m_ConsoleOutput, { 0, csbi.dwCursorPosition.Y + linecounter });
	SetConsoleTextAttribute(m_ConsoleOutput, csbi.wAttributes); // Reset Attributes after printing
	return SUCCESS;
}

status Console::PrintF(
	_In_z_ const wchar* Text,
	_In_opt_ ...
) {
	va_list Va; va_start(Va, Text);
	status Status = vPrintFormatW(Text, Va);
	va_end(Va);
	return Status;
}
status Console::PrintFEx(
	_In_z_   const wchar* Text,
	_In_opt_       err    ErrorLevel,
	_In_opt_              ...
) {
	va_list Va; va_start(Va, ErrorLevel);
	m_ErrorLevel = ErrorLevel;
	status Status = vPrintFormatW(Text, Va);
	va_end(Va);
	return Status;
}
#pragma endregion

class FileMap {
public:
	// Add support for readonly Pages
	FileMap(
		_In_z_ const wchar* szFile,
		_In_         dword  dwProtection = PAGE_READWRITE
	) {
		if ((m_hFile = CreateFileW(szFile, GENERIC_READWRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr)) == INVALID_HANDLE_VALUE)
			RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_HANDLE), 0, 0, nullptr);
		if (!(m_hMap = CreateFileMappingW(m_hFile, nullptr, dwProtection, 0, 0, nullptr)))
			RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_HANDLE), 0, 0, nullptr);
		if(!(m_Mapping = MapViewOfFile(m_hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
			RaiseException((dword)S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_POINTER), 0, 0, nullptr);
		MEMORY_BASIC_INFORMATION mbi;
		m_MappingSize = VirtualQuery(m_Mapping, &mbi, 0);
	}
	~FileMap() {
		UnmapViewOfFile(m_Mapping);
		CloseHandle(m_hMap);
		CloseHandle(m_hFile);
	}

	const void* Data() const { return m_Mapping; }
	const size_t& Size() const { return m_MappingSize; }

private:
	void*  m_Mapping;
	size_t m_MappingSize;
	handle m_hMap;
	handle m_hFile;
};