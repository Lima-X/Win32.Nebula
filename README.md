# \_rift
\_rift is a \[**P**\]acked and \[**P**\]rotected \[**M**\]odule \[**L**\]oader. (**PPML**)\
The Project is currently in development.

It aims to be able to launch a payload of choice in a protected environment hidden from the eyes of a user.\
It tries to achive this by using many well know malware techniques and even some less know ones.\
Im planning to add a lot more features to this even stuff outside of the original intentions such as a PE-File Infector.

## Parts
- Core:\
  As the name already says, its basically the main(core) part of this software...\
  Consisting of a Loader and the main Executable in the form of a encrypted Dll.

  - \_riftldr:\
    Main Executable containing the Core-Loader (S1) and its packed Resources,
    as well as many other Features and Services.

  - \_riftdll:\
    Main Payload Dll also containing the Loader-Stub (S2).\
    After initializazion, Controll will be given to this
    which can then be used as as a seperate "EntryPoint"
    that is fully protected by the loader.

  - \_riftutl:\
    Build utility used to compress/encrypt,
    obfuscate internal data, patch _rift and more.

- Sub:\
  These are sub parts like services or small standalones used by the core part.

  - \_riftmmi:\
    Dll Injector used to inject the RootKit Dll.\
    (Using parts of BlackBone/Xenos by DarthTon)\
    ((instead of being a standalone this will be moved into \_riftdll
    and \_riftldr in the future))

  - \_rifturk:\
    The RootKit Dll that will primarily hide Processes, Files and more.

## Feature List:
- Usermode Rootkit:
  - hide Processes
  - hide Files
  - hide Registry
  - limit access to specific Handles

- Anti Reverse-Engineering:
  - Anti analysis
  - Anti debugging
  - basic Anti Module injection
  - Binary integrity Checks
  - Self monitoring

- Function obfuscation
- String and Resource encryption
- Resource compression
- ManualMapping
- PE-File infection
- Process hollowing

more to come or to be added to the list...

## Info:
For more information about \_rift's internals look into the \[[Developer Reference](README2.md)\]
or into the plain sourcecode.

#### Note:
**Im aware that this is totaly malware.\
It is not meant to be used with melicous intend
and should only serve as a learning resource, demonstration or proof of concept (PoC).\
I do not encourage the spreading of malware as it is illegal and only contributes to trouble.\
! THE CREATOR IS NOT RESPONSIBLE FOR ANYTHING DONE USING THIS SOFTWARE !**

Incase this ever gets public I have decided so because I probably just wanted to do so..\
or maybe some other dumb reason, I mean there is nothing what imo would really prevent me from doing so,
there is alot of other shit public...\
Besides that, I programmed this (still do) just for fun and to learn to code and generally getting better,
other than that this project doesn't really serve a purpose besides being a showoff thing atmost.\
so this might basically serve as a learning resource for others about malware development.\
On top of that this might also be the last malware that i will be making for the time being,
as I plan on constantly updating and working on it, I hope... (I might do some side projects here and there).\
