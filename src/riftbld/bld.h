#pragma once

#include "nbp.h"

/* Commandline usage:
   "/[Operation]" : Specifies the operation to execute (this must be the first operand)
                    (The Forward Slash is reserved )

   "-[ParameterTag]:[Argument]" : Specifies the Argument for a specific Parameter(type)
                                  (this can appear in any order as long as it is specified after the operation specification)

   "-[FlagList]" : A list/string of flags that alter the behaviour of the selected operation
                   (this field is optional)

   An example command line could look like:
   """bld.exe /rc -fi:"ply.dll" -ce"""

   this would be then interpreted as:
   - Operation: rc (Add resource to Module)
   - Parameter: fi (File to be added)
     -> "ply.dll" (as the file being added)
   - Flags: -> c (compress inputfile)
            -> e (encrypt inputfile)

   The parser parses any commandline that is valid and
   translates it into a dynamically allocated structure internally,
   that is passed to the main programm.
   When finished the destructor for the object should be called.

   Spaces (' ') are used as command delimiters/terminaters.
   Quotes ('"') toggle the parsing of a section, meaning it is interpreted as one object and not split into multiple.
   Tags can have a maximum length of 4 chars (as they are strored in a 8byte value (UNICODE support))
*/

#define COL_SUCCESS  (FOREGROUND_GREEN)                                          // 0b0010 [S]
#define COL_INFO     (FOREGROUND_RED  | FOREGROUND_GREEN | FOREGROUND_BLUE)      // 0b0111 [+]
#define COL_QUESTION (FOREGROUND_BLUE |                    FOREGROUND_INTENSITY) // 0b1001 [?]
#define COL_WARNING  (FOREGROUND_RED  | FOREGROUND_GREEN                       ) // 0b1110 [!]
#define COL_ERROR    (FOREGROUND_RED  |                    FOREGROUND_INTENSITY) // 0b1100 [X]

#define CON_CREATE(Severity, Question, Color) ((Console::err)(((Severity << 6)) |\
                                              ((Question & 1) << 5) |\
                                              (Color & 0xf)))
#define CON_SUCCESS  CON_CREATE(SS_SUCCESS, false, COL_SUCCESS)
#define CON_INFO     CON_CREATE(SS_MESSAGE, false, COL_INFO)
#define CON_QUESTION CON_CREATE(SS_MESSAGE, true,  COL_QUESTION) // Currently Unsuppported
#define CON_ERROR    CON_CREATE(SS_ERROR,   false, COL_ERROR)
#define CON_WARNING  CON_CREATE(SS_WARNING, false, COL_WARNING)

#define CONVERT_ATOM(Char) (1 << (Char - L'a'))
#define CHECK_BMPFLAG(BitMap, Char) ((BitMap >> (Char - L'a')) & 1)

class Console {
public:
	/* Errorlevel Format:
	   BB         | B        | B        | BBBB
	   -----------+----------+----------+-----------
	   Errorlevel | Question | Reserved | Text Color */
	typedef unsigned char err;

	Console(_In_ dword pId = 0);
	~Console();

	status Cls();
	status PrintF(_In_z_ const wchar* Text, _In_opt_ ...);
	status PrintFEx(_In_opt_ err ErrorLevel, _In_z_ const wchar* Text, _In_opt_ ...);

protected:
	// Console Input/Output(/Error) Handle
	handle m_ConsoleInput;
	handle m_ConsoleOutput;

private:
	status vPrintFormatW(_In_z_ const wchar* Text, _In_opt_ va_list Va);

	CONSOLE_SCREEN_BUFFER_INFOEX m_csbiBackup;
	static u32    m_nRefCounter; // Class Reference Counter
	       void*  m_Buffer;      // Temporery Buffer (Pool) that will be used to Format, Get Text and more (multiple of Pagesize)
	       size_t m_BufferSize;  // The size of data inside the temporery Buffer (Pool)
	       err    m_ErrorLevel;  // The currently used ErrorLevel
};

class FileMap {
public:
	// Add support for readonly Pages
	FileMap() = delete;
	FileMap(
		_In_z_ const wchar* szFile,
		_In_         dword  dwProtection = PAGE_READWRITE
	);
	~FileMap();

	void*  Data() const;
	size_t Size() const;

private:
	void*  m_Mapping;
	size_t m_FileSize;
	handle m_hMap;
	handle m_hFile;
};

namespace img {
	u32 TranslateRvaToPa(_In_ handle Module, _In_ u32 Rva);
	status GetExportImageAddress(
		_In_ handle PeStream,
		_In_ const char* ExportName,
		_Out_ void*& ExportAddress
	);
}


inline Console* Con;
