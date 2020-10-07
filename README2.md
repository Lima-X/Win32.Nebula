# \_rift (Developer Reference)
This document serves as a quick & small reference sheet for \_rift,
giving basic information about its sourcecode such as:
- naming conventions
- build instructions
- anything else I decide to add

##### Note:
This document is currently deprecated and inaccurate,
as the sourcecode and main mechanisms of \_rift are currently heavily changing.\
For more accurate information refer to the sourceode or other notes.
```
Regex for removing comments:
(/\*(.|[\n])*?\*/)|(//.*)

C-MultilineComments: /\*(.|[\n])*?\*/
C++ Comments:        //.*
```

## Build Instructions
#### Building the Excutable:
- Build all Second Stage Dependencies
- Generate Wrap Key using _riftutl with /gk
- Encrypt Dependencies using _riftutl with /ec
- Build _rift 
- Patch _rift using _riftutl with /pa\
  (this will finalize the Application by patching in the proper md5's)

#### Embedding encrypted Strings:
- Generate Key using _riftutl with /gk
- Embed the exported Base64 Key in the sourcecode
- Encrypt and Encode all strings using _riftutl with /ec\
  and embed the encoded strings in the source

## Style/Naming Convention
#### Namespaces: 
Consist of 3 lowercase Letters.
```
dbg: Debugging related utilities (only included in debug builds)
rng: Contains a Xoshiro algorithim as a class and subfunctions to generate random bullshit
are: Containes Anti Reverse Engineering tools
    vma: VM Awareness (might be removed in the future)
    dli: Anti Dll Injection / Dll Injection Detection
    img: Image parsing utilities (includes section hashing)
con: Console Stuff (used for gui...)
utl: General purpose utilities
alg: Algorithim shit like a hex or base64 converter

To be implemented in the future:
mfi: Modle File Infector
svc: Service Shit (riftmmi might be renamed to riftsvc in the future)

mmm: Module Manual Mapper
fdt: Function Detouring
```

## FunctionNames:
`[Name][Suffix [opt]]`

#### Prefix:
Describes how a function is implemented and how it should be treated
```
NONE: not specified, this could mean anything
```

#### Suffix:
Describes what a function takes and how it should be used
```
NONE: not specified, this could mean anything
T:    Thread EntryPoint used to create a new thread
L:    Lambda
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
b:  bool / byte
w:  word
dw: dword
p:  Pointer to any Data (mostlikely void*, can be anything tho)
r:  reference
n:  Size of Data (size_t) (can also just be a normal number)
sz: ZeroTerminated String (wchar/char Array)
```