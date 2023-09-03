+++ 
title = "Using hook-updater to update old Android Frida hooks" 
date = "2023-08-31" 
author = "Joan Calabrés"  
description = "I've created a tool to update old Android Frida hooks. In this post I will show you how to use this tool and get updated hooks for your apps." 
+++

During my time as a *reverse engineer* I've created **Frida** hooks that were unusable after the app was updated. Once you have your first hooks on the target app you have something to compare with the udpdated app. If the updated app doesn't change obfuscation or code too much, we'll probably have old code that can be matched with updated code. Hopefully if not much differences are applied we'll get a match and then your hooks will be updated :)

## Why hook-updater?

I've created [hook-updater](https://github.com/jcalabres/hook-updater) to avoid repetitive tasks when I work with multiple mobile apps that are being updated constantly. Then I can update the hooks whenever I need, including when I want to avoid disruption in my tasks during app updates. 

## How it works?

The user specifies two different APKs for the same application. It also specifies the old hooks file and the new hooks file paths. Then, the solver of the tool will try to find similarities between the old smali files and the new smali files from the updated APK. 

The application uses multiple metrics and a score system to detect similarities between Java classes and Java methods that are in the Smali format.

>Smali is a languaje created for representing decompiled Android bytecodes and it can be obtained using the original [baksmali](https://github.com/JesusFreke/smali) tool or using other tools that have integrated it such as apktool or jadx.

## A real world example

I am working with a banking app that's version x.x.x.63. Since I was also working on other projects, that app got updated. Now the version I was working with doesn't work without updating it. Got to the Play Store and found the last version is x.x.x.67.

*hook-updater* works this way:

```bash
updater.py [-h] -old OLD -new NEW -hooks HOOKS -out OUT
```

### Obtaining the APK's

We will need both, the current APK and the updated one. In order to obtain them you can just dump your current/updated APK from your device.

In order to dump an installed apk you can just find the package name inside adb shell using: 

```bash 
pm list packages | grep -i app_name
```

Then find it's path by:

```bash
pm path package_name
```

Finally use adb pull to obtain all the APK's:

```bash
adb pull package_path
```

### Using hook-updater

```bash
python3 updater.py -old examples/*****/current.apk -new examples/*****/updated.apk -hooks  examples/*****/hooks.js -out updated_hooks.js
```

The original hooks look like this:

```js
let m = Java.use("l.b.c0.a.n");
m.c.implementation = function (bArr) {
    console.log(bytesToString(bArr));
    return this.c(bArr);
};

let a = Java.use("l.b.u0.e.a");
a.o.implementation = function (aVar, dVar, stringBuffer) {
    console.log(stringBuffer.toString());
    return this.o(aVar, dVar, stringBuffer);
};
```

The updated ones:

```js
let m = Java.use('l.b.b0.a.m');
m.c.overload().implementation = function (bArr) {
    console.log(bytesToString(bArr));
    return this.c(bArr);
};

let a = Java.use('l.b.s0.e.a');
a.o.overload("l.b.s0.a", "l.b.s0.e.e.a.d", "java.lang.StringBuffer").implementation = function (aVar, dVar, stringBuffer) {
    console.log(stringBuffer.toString());
    return this.o(aVar, dVar, stringBuffer);
};
```

As you can see the hooks are updated. So far, I've tried these hooks and they work correctly. 

Hopefully hook-updater will work in apps that doesn't apply a big effort in obfuscation on every release.

## About hook-updater

There's some detailed information about hook-updater on its [repository](https://github.com/jcalabres/hook-updater), please check it for more information and don't hesitate to collaborate arround it.