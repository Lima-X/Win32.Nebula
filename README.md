# Win32.Nebula
Nebula is a \[**P**\]acked and \[**P**\]rotected \[**M**\]odule \[**L**\]oader. (**PPML**)\
Named after a space phenomenon that describes a interstellar cloud\
(its internally still refered to as _rift or rift as this was the original Name)

Nebula aims to be able to launch a payload of choice in a protected environment hidden from the eyes of a user.\
It tries to achive this by using many well know malware techniques and even some less know ones.\
Im planning to add a lot more features to this even stuff outside of the original intentions such as a PE-File infector.

This project is currently in development and currently serves as a POC or template to build onto.\
In the future this could be build out into a fully fletched "basic"-protector.

## Components:
- **riftldr:**\
  Main executable containing the Core-Loader (S1 & S2) and its packed resources,
  as well as many other features and services.

- **riftbld:**\
  Build utility used to compress/encrypt,
  obfuscate internal data, patch Nebula and more.\
  what will be featured in her only depends on what i plan to add in riftldr itself


- **riftrk:**\
  The rootKit dll that will primarily hide processes, files and maybe more.

## Feature List:
Note: Some of them have not been implmented yet...

- Usermode Rootkit:
  - hide processes
  - hide files
  - hide registry
  - limit access to specific Handles

- Anti Reverse-Engineering:
  - Anti analysis
  - Anti debugging
  - basic anti module injection
  - Binary integrity checks
  - Self decryption/decompression
  - Self monitoring

General:
- Function obfuscation
- String and resource encryption
- Resource compression
- Manualmapping for modules and remote processes
- PE-File infection
- Process hollowing
- Threadhijacking

more to come or to be added to the list...

## Disclaimer:
**Im aware that this is totaly malware or could be used for malware.\
It is not meant to be used with malicous intends
and should only serve as a learning resource,
demonstration or proof of concept (PoC).**

**I do not encourage the spreading of malware for several obvious reasons.\
! THE CREATOR IS NOT RESPONSIBLE FOR ANYTHING DONE USING THIS SOFTWARE !**

### Why did I decide to make this public then ?
The reason is the same as why you can find alot of open source projects that could be used for malicous purposes.\
Or why you can find books about how Rootkits work and how to build them, as well as other stuff.

It serves as a learning resource and most of the techniques contained are already publicly optainable,\
the actual bad guys already have all the knowledge if not even more...
