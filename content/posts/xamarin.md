+++ 
title = "Quick Xamarin RE Guide" 
date = "2023-08-30" 
author = "Joan Calabrés"  
description = "Get started with Xamarin reverse engineering with this quick guide."
+++

## What is Xamarin?

Xamarin is an open source platform used to compile modern applications with a great performance for iOS, Android and Windows with .NET. Xamarin is an abstraction layer that administrates shared code with the code of the underlying platform. Xamarin is executed in an administered environment that performs memory assignation and garbage collection.

## How it works?

In this diagram we show the general architecture of a Xamarin multi platform application. Xamarin lets the developers to write a native GUI for every platform and write the logic in C# that will be shared with all the platforms. In most of the cases, with Xamarin, we can share the 80% of the code of the application. Xamarin is added to .NET that automatically controls memory assignation and does the interoperability between the platforms.

{{< image src="/posts/img/xamarin/platform.png" alt="Xamarin Platform" position="center" style="border-radius: 8px;height: 250px;">}}

## Android Xamarin Compilation

C# is compiled to IL and packaged with MonoVM + JIT’ing. Unused classes in the framework are stripped out during linking. The application runs side by side with Java/ART (Android runtime) and interacts with the native types via JNI.

## Where to find Shared Code?

Shared Code is compiled into static .DLL libraries, these libraries are found into the `assemblies` folder of your root apk directory.  You will find in this directory multiple .DLL files including the `Mono.Android.dll` that is in charge of the Mono runtime, also you will find other libraries related with third party libraries or the main code of the application. 

## How to decompile .DLL code?

The payload of the .DLL libraries is compressed using the **lz4** algorithm, this payloads have the instructions of the **IL** (Intermediate Language) that can be decompiled using different programs such as ILSpy. The following image represents the format:

{{< image src="/posts/img/xamarin/binary_format.png" alt="Binary Format" position="left" style="border-radius: 8px;height: 250px;">}}

In order to decompress the payloads inside the .DLL files we can use the following bash script:

```python
#!/usr/bin/python
import sys, struct, lz4.block, os.path

if len(sys.argv) != 2:
    sys.exit("[i] Usage: " + sys.argv[0]  + " in_file.dll")
in_file = sys.argv[1]
with open(in_file, "rb") as compressed_file:
    compressed_data = compressed_file.read()

header = compressed_data[:4]

if header != b"XALZ":
    sys.exit("[!] Wrong header, aborting...!")

packed_payload_len = compressed_data[8:12]
unpacked_payload_len = struct.unpack('<I', packed_payload_len)[0]
compressed_payload = compressed_data[12:]
decompressed_payload = lz4.block.decompress(compressed_payload, uncompressed_size=unpacked_payload_len)

out_file = in_file.rsplit(".",1)[0] + "_out.dll"

if os.path.isfile(out_file):
    sys.exit("[!] Output file [" + out_file  + "] already exists, aborting...!")

with open(out_file, "wb") as decompressed_file:
    decompressed_file.write(decompressed_payload)
    print("[i] Success!")
    print("[i] File [" + out_file + "] was created as result!")
```

You can use it using the following format:  `python3 [de-lz4.py](http://de-lz4.py) {PATH_TO_DLL}`. A file with the suffix `_out.dll` will be added to the same path.

## Decompiling .NET code

You can download `ILSpy` a decompiler to inspect **IL** bytecode. Later on, open the .DLL that you want to inspect with it. It is recommended to put part of the assemblies that you want to reverse in order to obtain cross-references between different .DLL files.

## Hooking .NET Code

A GitHub repository has been created with the API for the Mono runtime https://github.com/freehuntx/frida-mono-api. The https://github.com/NorthwaveSecurity/fridax tool integrates this API with Frida in order to allow you to easily modify the .NET binary inside a Xamarin application on runtime. 

### Installation

For the correct functionality of this tool, you will need to use an old version of frida-server. In that case **14.0.8** is working well with this tool. New versions might fail as fridax dependencies are outdated and assembled to work with old versions.

Follow the steps inside the GitHub repository. Be sure to have Node **14.0.0**, if not, the installation will fail as Fridax was created with older versions of Node. An easy way to have multiple Node installations is to install https://github.com/nvm-sh/nvm. Later on, install node 14 and change the default node to use:

`nvm install 14`

`nvm use 14`

### Usage

For usb devices you can use:

`./fridax.js inject --device "usb”`

There are multiple templates inside the **fridax** folder, examples. This folder contains different templates for hooking aot/jit binaries. 

## Bypassing Cert Pinning

### How it’s implemented?

There are two entry points to override certificate validation, depending on whether .NET Framework or .NET Core is being used. Mono has recently moved to .NET Code APIs

Prior to .NET Code validation occurs through `System.Net.ServicePointManager.ServerCertificateValidationCallback` which is a static property containing the function to call when validating a certificate. All `HttpClient` instances will call the same function, *so only one function needs to be hooked*.

Starting with .NET Core, however, the HTTP stack has been refactored such that each `HttpClient` has its own `HttpClientHandler` exposing a `ServerCertificateCustomValidationCallback` property. This handler is injected into the `HttpClient` at construction time and is frozen after the first HTTP call to prevent modification. This scenario is much more difficult as it requires knowledge of every `HttpClient` instance and their location in memory at runtime.

### Fridax hook

```jsx
import { MonoApiHelper, MonoApi } from '../vendors/frida-mono-api'
import ClassHelper from '../libraries/class_helper'

// The root AppDomain is the initial domain created by the runtime when it is initialized.
const domain = MonoApi.mono_get_root_domain()

// Get System.Net.Http from memory
let status = Memory.alloc(0x1000);
let http = MonoApi.mono_assembly_load_with_partial_name(Memory.allocUtf8String('System.Net.Http'), status);
let img = MonoApi.mono_assembly_get_image(http);

// Get HttpClientHandler class and constructor
var kHandler = MonoApi.mono_class_from_name(img, Memory.allocUtf8String('System.Net.Http'), Memory.allocUtf8String('HttpClientHandler'));
var ctor = MonoApiHelper.ClassGetMethodFromName(kHandler, 'CreateDefaultHandler');  

// Get HttpRequestMessage class and ToString method
let request = MonoApi.mono_class_from_name(img, Memory.allocUtf8String('System.Net.Http'), Memory.allocUtf8String('HttpRequestMessage'));
let toString = MonoApiHelper.ClassGetMethodFromName(request, 'ToString');

var INJECTED = {};

if (kHandler) {
    // Hook HttpMessageInvoker.SendAsync
    var kInvoker = MonoApi.mono_class_from_name(img, Memory.allocUtf8String('System.Net.Http'), Memory.allocUtf8String('HttpMessageInvoker'));
    // Attach interceptor and fish out the first method argument
    MonoApiHelper.Intercept(kInvoker, 'SendAsync', {
        onEnter: function(args) {
            // Print HTTP Request
						console.log(MonoApiHelper.StringToUtf8(MonoApiHelper.RuntimeInvoke(toString, args[1])));
            
						// Get the HTTP handler 
						var self = args[0];
            var handler = MonoApiHelper.ClassGetFieldFromName(kInvoker, '_handler');
            var cur = MonoApiHelper.FieldGetValueObject(handler, self);
            if (INJECTED[cur]) return; // Already bypassed.

            // Create a new handler per HttpClient to avoid dispose() causing a crash.
            var pClientHandler = MonoApiHelper.RuntimeInvoke(ctor, NULL); // instance is NULL for static methods.
            console.log("[+] New HttpClientHandler VA=".concat(pClientHandler));
            MonoApi.mono_field_set_value(self, handler, pClientHandler);
            console.log("[+] Injected default handler for Client=".concat(self));
            INJECTED[pClientHandler] = true; // TODO: cleanup on HttpClient dispose.
        }
    })
}
console.log(`Xamarin pinning bypass attached and ready.`)
```

## Resources

* [Reverse Engineering a Xamarin Application. " Security Grind](https://securitygrind.com/reverse-engineering-a-xamarin-application/)

* [Bypassing Xamarin Certificate Pinning on Android - GoSecure](https://www.gosecure.net/blog/2020/04/06/bypassing-xamarin-certificate-pinning-on-android/)

* [https://github.com/NorthwaveSecurity/fridax](https://github.com/NorthwaveSecurity/fridax)