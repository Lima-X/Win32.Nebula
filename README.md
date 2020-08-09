# \_rift (PDL)
Packed(compressed & encryped) Dll Loader.

## \_riftldr
Main Executable containing the Core-Loader (S1) and its packed Resources,
as well as many other Features.

#### Features:
- [x] VMawarness
- [X] Anti Debug
- [ ] Anti Dll Injection (Module enumeration & LoadLibrary Hooking)
- [ ] Process enfrocement/persistency (selfmonitoring & BreakOnTermination)
- [x] Resource Decryption/Decompression (AES128CBC & LZMS)
- [x] String Deobfuscation (Base64 & AES128CBC)
- [x] TLS Callback for AntiRE
- [ ] Memory Section Hashing (reversing relocs)

## \_riftdll
Main Payload Dll also containing the Loader-Stub (S2).\
after initializazion Controll will be given to this

#### Features:
- [ ] Stub
  - [ ] Autostart (Registry Key)
- [x] UAC Bypass (RAiLaunchAdminProcess & DebugObject)
- [ ] Executable "Infector" (Packing as Resource)

## \_riftInject
Dll Injector used to inject the RootKit Dll.\
(Using parts of BlackBone/Xenos by DarthTon)

#### Features:
- [ ] Unlink Module
- [ ] Erase PE Header

## \_riftRoot
The RootKit Dll that will primarily hide Processes and Files.

#### Features:
- [ ] Hook NtQueryDirectoryFile
- [ ] Hook NtQuerySystemInformation

## \_riftTool
Build utility used to compress/encrypt, obfuscate internal data and patch _rift.

#### Features:
- [x] Generate Master Warp Key
- [x] Compress/Encrypt File
- [x] Decrypt/Decompress File
- [ ] Obfuscate Strings (AES128CBC & Base64)
- [x] Md5 Patcher for SectionHashing

# Build Instructions
## Building the Excutable:
- Build all Second Stage Dependencies
- Generate Wrap Key using _riftTool with /gk
- Encrypt Dependencies using _riftTool with /ec
- Build _rift 
- Patch _rift using _riftTool with /pa\
  (this will finalize the Application by patching in the proper md5's)

## Embedding encrypted Strings:
- Generate Key using _riftTool with /gk
- Embed the exported Base64 Key in the sourcecode
- Encrypt and Encode all strings using _riftTool with /ec\
  and embed the encoded strings in the source

# Style/Naming Convention
## FunctionNames:
`[Prefix][Name][Suffix]`

#### Prefix:
Describes how a function is implemented and how it should be treated
```
NONE: not specified, this could mean anything
E:    Exported, these functions are free to use externaly
I:    Internal, these functions are private and shouldn't be used externaly
H:    Hook Function (only applies to detouring related)
R:    Real Function (only applies to detouring related)
```

#### Suffic:
Describes what a function takes and how it should be used
```
NONE: not specified, this could mean anything
T:    Thread EntryPoint used to create a new thread
C/H:  CallBack / Hook Function
A/W:  Ansi/Unicode Paramenters
```

## VariableNames:
[NameSpace][Prefix][Name][Suffix]

#### Namespace:
Describes where a Variable can be used
```
NONE: not in a global/unit scope
g_:   Global, can be used anywhere
e_:   External, like global except that its only shared between specific units
l_:   Local, can only be used in the translation unit of the declaration
```

#### Prefix:
Describes the Datatype of the Variable in a short from
```
C:
    b:  BOOL / byte
    w:  WORD
    dw: DWORD
    p:  Pointer to any Data (void*)
    n:  Size of Data (size_t)
    sz: ZeroTerminated String (WCHAR/(CHAR) Array)
    a(N): Array of with Size of (N)

WinAPI:
    h:  Handle / Module
    ah: BCrypt Algorithm Handle
    kh: BCrypt Key Handle
    hh: BCrypt Hash Handle
    ch: De/Compressor Handle
    cs: Critical Section Object
```