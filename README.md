# \_rift (PML)
Packed(compressed & encryped) Module Loader.

#### Note:
Basically most of the shit standing here is deprecated or inaccurate as it probably already has changed,
so... dont trust this readme and rather refer to the sourcecode and its comments I left.\
(i could actually just delete this file but whatever, idrc.)

Incase this ever gets public I have decided so because I probably just wanted to do so..\
or maybe some other dumb reason, I mean there is nothing what imo would really prevent me from doing so,
there is alot of other shit public...\
Besides that, I programmed this (still do) just for fun and to learn to code an generally getting better,
other than that this project doesn't really serve a purpose besides being a showoff thing atmost.\
so this might basically serve as a learning resource for others about malware development.\
On top of that this might also be the last malware that i will be making for the time being,
as I plan on constantly updating and working on it, I hope... (I might do some side projects here and there).\

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
- [x] Memory Section Hashing (reversing relocs)

## \_riftdll
Main Payload Dll also containing the Loader-Stub (S2).\
after initializazion Controll will be given to this

#### Features:
- [ ] Stub
  - [ ] Autostart (Registry Key)
- [x] UAC Bypass (RAiLaunchAdminProcess & DebugObject)
- [ ] Executable "Infector" (Appending the executable to with shellcode and extracting it)

## \_riftmmi
Dll Injector used to inject the RootKit Dll.\
(Using parts of BlackBone/Xenos by DarthTon)

#### Features:
- [ ] Unlink Module
- [ ] Erase PE Header

## \_rifturk
The RootKit Dll that will primarily hide Processes and Files.

#### Features:
- [ ] Hook NtQueryDirectoryFile
- [ ] Hook NtQuerySystemInformation

## \_riftutl
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
- Generate Wrap Key using _riftutl with /gk
- Encrypt Dependencies using _riftutl with /ec
- Build _rift 
- Patch _rift using _riftutl with /pa\
  (this will finalize the Application by patching in the proper md5's)

## Embedding encrypted Strings:
- Generate Key using _riftutl with /gk
- Embed the exported Base64 Key in the sourcecode
- Encrypt and Encode all strings using _riftutl with /ec\
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
Cb/H: CallBack / Hook Function
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
m_:   private Class Member
p_:   protected Class Member 
```

#### Prefix:
Describes the Datatype of the Variable in a short from
```
C:
    b:  bool / byte
    w:  word
    dw: dword
    p:  Pointer to any Data (mostlikely void*, can be anything tho)
    r:  reference
    n:  Size of Data (size_t) (can also just be a normal number)
    sz: ZeroTerminated String (wchar/char Array)
```