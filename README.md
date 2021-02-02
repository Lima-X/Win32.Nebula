# Win32.Nebula
Nebula is a **P**acked and **P**rotected **M**odule **L**oader. (**PPML**)\
Named after a space phenomenon that describes a interstellar cloud.\
(it may internally still be refered to as _rift or rift)

Nebula aims to be able to launch a payload of choice in a protected environment.\
It tries to achive this by using various techniques used to obfuscated and protect code,\
these include well known tricks commonly used in e.g. malware, anticheats and others.\
It serves as an absolute base and will provide a small framework through an SDK and API.\
This Framwork will have basic functionality in order to control the loader from a payload,\
but will be extensible through a dynamic service interface allowing extenstions,
that can be attached to Nebula, to allow registering functions that the payload may use.

This project is currently in development and currently serves as a POC or template to build onto.\
In the future this could be build out into a fully fledged "basic"-protector.

## Components:
Nebula is mainly split into 2 components, the base (loader) and its builder utility.

- The loader will be shiped in the form of a static lib,
  which would be linked into a payload executable by setting it up to be the entrypoint,
  the builder would later finalize the image by obfuscating the rest and properly linking up the functions.

- The builder that is responsible for patching, crypting, packing and generally messing with binaries.\
  It provides the interface for modifying images used by the loader or the loader itself.\
  It serves as a tool to finalize the binary into and turn it into a proper executable image.

## Usage:
Note: This is currently only how it is supposed to be designed at the current state.

Nebula is shipped as a static lib, around max 20kb, with a single header sdk.\
A client can simply code a programm with an by Nebula defined entrypoint and link in the static lib,
(he can either tell the linker to use the lib as an entrypoint or a custom entry that calls the lib entry).

The TlsCallback inside the lib will be responsible for starting and as well as shutting down major functionality of the library,
this also being the reason why the client wont be able to use compiler implemented TLS (doubt it is that important).

The SDK provides an interface that should be used by client code,
(due to it being a static lib the client has full access to internal API's, this is not recommended).\
The SDK exposes through the client entrypoint the major functions for the ServiceManager,
this manager on the other hand exposes all public API's of Nebuala
(it is not limited to manage public API's only tho and can also expose internal private API's used by internals through the service call system).\
The ServiceManager is fully dynamic and allows for Client code as well as plugins to register services as well as unregister them.\
This allows client code to securely access API's with a well defined signature and interface.

A PlugingAPI is also planned allowing to load a packed pluging from a buffer, resource or file into the host process.\
As of now, these Plugins by design will be able to import systemdependencies or dll's normaly,
however they wont be able to import other plugins by design, they are still free to subload plugins.

## Disclaimer:
**Im totally aware that this could be used for malware.**\
It is not meant to be used for malicous intends and should only serve as a learning resource,
demonstration or proof of concept (PoC).

**I do not encourage the spreading of malware for several obvious reasons.\
! THE CREATOR IS NOT RESPONSIBLE FOR ANYTHING DONE USING THIS SOFTWARE !**

### Why did I decide to make this public then ?
The reason is the same as why you can find alot of other open source projects that could be used for malicous purposes.\
Or why you can find books about how rootkits work and how to build them, as well as other stuff.

It serves as a learning resource and most of the techniques contained are already publicly optainable,\
the actual bad guys already have all the knowledge if not even more...
