+++ 
title = "Bypassing root detection on Pixel3 devices" 
date = "2022-02-27" 
author = "Joan Calabrés"  
description = "Adapting the CVE-2020-0041 privilege escalation exploit for Pixel3 family devices in order to bypass root detection." 
+++

There are different root frameworks that can be used on Android in order to obtain root privileges. Usually, during Android application security evaluations, root detection is tested in different ways. Application countermeasures such as root detection are easy to bypass in most of the Android applications and sometimes without the use of reverse engineering techniques; however, as I've been seen during the analysis of banking applications, bypassing root detection on these applications can be hard and time consuming due to the level of obfuscation and countermeasures applied.

