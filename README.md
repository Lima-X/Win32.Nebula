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

## \_riftdll
Main Payload Dll also containing the Loader-Stub (S2).\
after initializazion Controll will be given to this

#### Features:
- [ ] Stub
  - [ ] Autostart (Registry Key)
- [ ] UAC Bypass (RAiLaunchAdminProcess & DebugObject)
- [ ] Executable "Infector" (Packing as Resource)

## \_riftInject:
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

## \_riftCrypt
Build utility used to encrypt/compress and obfuscate internal data for \_rift.

#### Features:
- [x] Generate Master Warp Key
- [x] Compress/Encrypt File
- [x] Decrypt/Decompress File
- [ ] Obfuscate Strings (AES128CBC & Base64)