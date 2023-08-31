+++ 
title = "Using hook-updater to update old Frida hooks" 
date = "2023-08-31" 
author = "Joan Calabrés"  
description = "I've created a tool to update old Frida hooks. In this post I will show you how to use this tool and get updated hooks for your apps." 
+++

During my time as a *reverse engineer* I've created **Frida** hooks that were unusable after the app was updated. Once you have your first hooks on the target app you have something to compare with the udpdated app. If the updated app doesn't change obfuscation or code too much, we'll probably have old code that can be matched with updated code. Hopefully if not much differences are applied we'll get a match and then your hooks will be updated :)

## Why hook-updater?

I've created [hook-updater](https://github.com/jcalabres/hook-updater) to avoid repetitive tasks when I work with multiple mobile apps that are being updated constantly. Then I can update the hooks whenever I need, including when I want to avoid disruption in my tasks during app updates. 

## How it works?

The user specifies two different APKs for the same application. It also specifies the old hooks file and the new hooks file paths. Then, the solver of the tool will try to find similarities between the old smali files and the new smali files from the updated APK. 

The application uses multiple metrics and a score system to detect similarities between Java classes and Java methods that are in the Smali format.

>Smali is a languaje created for representing decompiled Android bytecodes and it can be obtained using the original [baksmali](https://github.com/JesusFreke/smali) tool or using other tools that have integrated it such as apktool or jadx.

## A real world example

**TODO**

## More information

There's some detailed information about hook-updater on its [repository](https://github.com/jcalabres/hook-updater), please check it for more information and don't hesitate to collaborate arround it.