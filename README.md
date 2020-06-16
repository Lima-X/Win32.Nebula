# \_rift (PDL)
Packed(compressed & encryped) Dll Loader.

## \_rift
Main Executable containing the Core-Loader (S1) and its packed Resources,
as well as many other Features.

#### Features:
- [x] VMawarness
- [X] Anti Debug
- [ ] Anti Dll Injection (Module enumeration & LoadLibrary Hooking)
- [ ] Process enfrocement/persistency (selfmonitoring & BreakOnTermination)
- [ ] Resource Decryption/Decompression (AES128CBC & LZMS)
- [ ] String Deobfuscation (Base64 & AES128CBC)
- [x] TLS Callback for AntiRE
- [x] Code/Text Section Hashing\
      (Upgrade to Hash all Sections (including Section Containing Hash)

## \_riftdll
Main Payload Dll also containing the Loader-Stub (S2).\
after initializazion Controll will be given to this

#### Features:
- [ ] Stub
  - [ ] Autostart (Registry Key)
- [ ] UAC Bypass (RAiLaunchAdminProcess & DebugObject)
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
- [x] Md5 Patcher for SectionHashing\
      (Upgrade to Hash all Sections (including Section Containing Hash)

# Build Instructions
## Building the Excutable:
- Build all Second Stage Dependencies
- Generate Wrap Key using _riftTool with /gk
- Encrypt Dependencies using _riftTool with /ec
- Build _rift 
- Patch _rift using _riftTool with /pa\
  (this will finalize the Application by patching in the proper MD5's)

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
Non: not specified, this could mean anything
E:   Exported, these functions are free to use externaly
I:   Internal, these functions are private and shouldn't be used externaly
H:   Hook Function (only applies to detouring related)
R:   Real Function (only applies to detouring related)
```

## VariableNames:
[NameSpace][Prefix][Name][Suffix]

#### Namespace:
Describes where a Variable can be used
```
g_: Global, can be used anywhere
l_: Local, can only be used in the translation unit oof the declaration
e_: external, like local except that it is shared between specific units
```

#### Prefix:
Describes the Datatype of the Variable in a short from
```
C:
    b:  BOOL / BYTE
    w:  WORD
    dw: DWORD
    p:  Pointer to any Data (PVOID)
    n:  Size of Data (SIZE_T)
    sz: ZeroTerminated String (WCHAR/(CHAR) Array)
    a(N): Array of with Size of (N)

WinAPI:
    h: Handle / Module
    ah: BCrypt Algorithm Handle
    kh: BCrypt Key Handle
    hh: BCrypt Hash Handle
    ch: De/Compressor Handle
    cs: Critical Section Object
```