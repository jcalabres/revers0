+++ 
title = "CyberTruckChallenge" 
date = "2019-09-08" 
author = "Joan Calabrés"  
description = "Oh my god, hacking cars... never too easy!" 
+++

Hello, in this post I'll show you <a href="https://gist.github.com/jcalabres/f90c601d4f02874f34f6974e657ae3f5">my solutions</a> for the CyberTruckChallenge of 2019. 

The <a href="https://github.com/nowsecure/cybertruckchallenge19">CyberTruckChallenge</a> is a workshop about Android Security sponsored by NowSecure and created by 
<a href="https://github.com/enovella">@enovella</a>. 

*note: the challenges presented in this post are for beginners; however, if you don't have basic knowledge about mobile RE, this is not intended to be a tutorial.*

## Table of Contents
1. [Description](#description)
2. [First Steps](#first_steps)
3. [Challenge 1](#challenge1)
4. [Challenge 2](#challenge2)
4. [Challenge 3](#challenge3)

<a name="description">
## Description

*"A new mobile remote keyless system "CyberTruck" has been implemented by one of the most well-known car security companies "NowSecure Mobile Vehicles". The car security company has ensured that the system is entirely uncrackable and therefore attackers will not be able to recover secrets within the mobile application.*

*If you are an experienced Android reverser, then enable the tamperproof button to harden the application before unlocking your cars. Your goal will consist on recovering up to 6 secrets in the application."*
</a>

## Tools

The main tools needed for these solutions are listed below:

* <a href="https://www.frida.re">**Frida**</a> 
* <a href="https://github.com/skylot/jadx">**jadx**</a> 
* <a href="https://ghidra-sre.org">**Ghidra**</a> 

<a name="first_steps">
## First Steps

This challenge is presented as an APK. The first task of a reverse engineer consists on having knowledge about the target. First we'll need to install the application in our Android device **(API=>24)**. In my case I'm using the **Android Studio Emulator** with a x86 developer ROM that comes with root permissions.

```bash
adb install cybertruck19.apk
```

<img src="/posts/img/cybertruck.png" alt="CyberTruck APK" style="float:left;height:400px;margin:0 20px 10px 0">

In the image we can see that the application is very simple. We've a button to unlock all the cars, we can suppose that using this button, different cryptographic keys are used to unlock each of the 3 cars. 

Furthermore, the **TamperProof** radio button is activating the tamper protection, if you don't have Frida in your device, the **TamperProof** won't detect that the device is compromised, because this protection only looks for **Frida**.

The challenge rules specify that the **TamperProof** protection needs to be activated for solving the challenge correctly. As the challenge is intended to be solved with **Frida**, if the application detects it, it'll be closed.

The main objective now is to deactivate the tamper protection and use **Frida** to hook the different sensitive functions that carry the cryptographic keys.

We can use an Android Decompiler to recover a human-readable **Smali/Java code**. I'm using a proprietary and expensive option called JEB, but you can use a free Decompiler like **jadx**.


<img src="/posts/img/packages.png" alt="Packages" style="float:left;height:200px;margin:0 20px 10px 0">

If we read the manifest file of the Android Application, we can see the first entry of the application.

```bash
android:name="org.nowsecure.cybertruck.MainActivity"
```

Having this information in our hand, we can decompile the MainActivity in order to know the implementation of the program. In the OnCreate method of the activity, different listeners for the multiple buttons are set up.

## Countermeasures

One of the listeners is setting up a function for responding to an activation action. The class HookDetector is used with the method **isFridaServerInDevice**, if **Frida** is detected on the device, the application will notify the user and it will be closed.

```java
if((arg8) && (new HookDetector().isFridaServerInDevice())) {
    Toast.makeText(MainActivity.l(), "Tampering detected!", 0).show();
    new CountDownTimer(2000, 1000) {
        public void onFinish() {
            System.exit(0);
        }
        public void onTick(long arg1) {
        }
    }.start();
}
```

After decompiling the **Frida** countermeasure, we can see that the implementation is very simple and it's only checking different possible locations in which the **Frida** server may be in the device. If the Frida server is found, it will return True, otherwise False.

```java
public boolean isFridaServerInDevice() {
    if(!new File("/data/local/tmp/Frida-server").exists() 
        && !new File("/data/local/tmp/re.Frida.server").exists() 
        && !new File("/sdcard/re.Frida.server").exists()) {
        if(new File("/sdcard/Frida-server").exists()) {
        }
        else {
            return 0;
        }
    }
    Log.d("CyberTruckChallenge", "TAMPERPROOF [0] - Hooking detector trigger due...");
    return 1;
}
```

Before going through all the different challenges of the CyberTruckChallenge, we should bypass the protection in order to do the challenge with the tamper protection activated.

Frida works as a **Client/Server** architecture. We'll push the server on **/data/local/tmp/** and give it execution permissions.

```bash 
adb root 
adb push Frida-server-12.6.18-android-x86 /data/local/tmp/
adb shell chmod +x /data/local/tmp/Frida-server-12.6.18-android-x86
adb shell /data/local/tmp/Frida-server-12.6.18-android-x86
```

After that, we can create our first hook with Frida to bypass the protection, it'll be a .js file.

```javascript
Java.perform(function () {
  // Class to hook is defined here
  var hookDetector = Java.use('org.nowsecure.cybertruck.detections.HookDetector');
  // Function to hook is defined here
  hookDetector.isFridaServerInDevice.implementation = function (v) {
    console.log('isFridaServerInDevice')
    return false
  };
});
```

We'll need to load our Frida script into our Android device or emulator. After that, we can activate the tamper protection and continue with the challenges. In this case Frida is used with the USB and spawn option. 

```bash
frida -Uf org.nowsecure.cybertruck -l truck.js
```
</a>

<a name="challenge1">
## Challenge 1

In the MainActivity, we can see that the listener for the button that unlocks the cars is calling the k function. The k function calls the class that has the secrets of our **Challenge1**.

```java
protected void k() {
    new Challenge1();
    new a(MainActivity.j);
    this.init();
}
```

The **Challenge1** class is composed of two important methods: **generateKey()** and **generateDynamicKey(byte[] arg5)**. In the constructor of the class, the generateKey will be called and it will call the generateDynamicKey with a message to encrypt. The creation of the key will be done using a hardcoded key.

```java
 protected byte[] generateDynamicKey(byte[] arg5) {
    SecretKey v0 = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec("s3cr3t$_n3veR_mUst_bE_h4rdc0d3d_m4t3!".getBytes()));
    Cipher v1 = Cipher.getInstance("DES");
    v1.init(1, ((Key)v0));
    return v1.doFinal(arg5);
}
```

This will be our first secret, but now we need the token generated with our key. This token will be our second and final secret of the Challenge1, and it's generated in the encryption of the message with the static key. We'll use Frida again to hook the generation of the key in order to obtain it.

```javascript
var challenge1 = Java.use('org.nowsecure.cybertruck.keygenerators.Challenge1')
challenge1.generateDynamicKey.implementation = function (v) {
   var secret=this.generateDynamicKey(v)
   send(ba2hex(secret));
   return secret
}
```

As the code states, we're printing our key in hexadecimal format, but we're not changing the real return of the function. Below are the two secrets of this challenge.

```txt
[SECRET1] s3cr3t$_n3veR_mUst_bE_h4rdc0d3d_m4t3!
[SECRET2] 046e04ff67535d25dfea022033fcaaf23606b95a5c07a8c6
```
</a>

<a name="challenge2">
## Challenge 2

In the same package as the **Challenge1** class, we can find another class called a. If we decompile this class we'll see that the constructor is calling another constructor that is using a hardcoded key inside a file. The implementation will use the key extracted from the file and a String to cipher in order to generate our token.

```java
public a(Context arg2){
    super();
    byte[] v0 = "uncr4ck4ble_k3yle$$".getBytes();
    byte[] v2 = this.a(arg2);
    try {
        this.a(v0, v2);
        return;
    }
```

The file of the key is called ch2.key. This key is hardcoded in the assets of the application and it's the first secret of this challenge.

```java
v5_1 = arg5.getAssets().open("ch2.key");
```

The second secret of this challenge is the generated token that can be found on the this.a(v0,v2) function. 

```java
protected byte[] a(byte[] arg3, byte[] arg4) {
    SecretKeySpec v0 = new SecretKeySpec(arg4, "AES");
    Cipher v4 = Cipher.getInstance("AES/ECB/PKCS7Padding");
    v4.init(1, ((Key)v0));
    return v4.doFinal(arg3);
}
```

Adapting the script used in **Challenge1**, we can make the **Challenge2** version. We must be aware of the overload that is needed to specify the correct signature of the function. We also must be aware that the function is a protected one and it must be accessed through an instance of the class.

```javascript
var challenge2 = Java.use('org.nowsecure.cybertruck.keygenerators.a')
challenge2.a.overload('[B', '[B').implementation = function (v1,v2) {
    var secret=this.a.overload('[B', '[B').call(this,v1,v2)
    send(ba2hex(secret));
    return secret
}
```

Below are the two secrets of this challenge (the third and fourth of the overall challenge).

```txt
[SECRET3] d474_47_r357_mu57_pR073C73D700!!
[SECRET4] 512100f7cc50c76906d23181aff63f0d642b3d947f75d360b6b15447540e4f16
```
</a>

<a name="challenge3">
## Challenge 3

The last challenge is performed on the native layer. It's loaded in the MainActivity through the **System.loadLibrary** function.

```java
static {
    System.loadLibrary("native-lib");
}
```

For this challenge, we'll need to extract the library for the APK. As an APK is a zip file, we can just decompress it an extract the native-lib library from the lib folder.

```bash
unzip cybertruck19.apk -d challenge
cp ./ challenge/lib/x86/libnative-lib.so
```

Now we'll need a disassembler, we can use the new tool from the NSA named **Ghidra**. By analyzing the strings of the binary, we can find the first secret of this challenge.

By inspecting the different functions of the binary, we can see the main function of the native lib: **Java_org_nowsecure_cybertruck_MainActivity_init**. A while statement can be seen using the graph view or decompiling the code. The while is performing arithmetic operations with different bytes in order to get the token. 

In this case, we need to Intercept an address at a certain offset from the main function that is performing the arithmetic operations. 

<img src="/posts/img/flow.png" alt="Native Flow" style="height:400px;margin:0 20px 10px 0">

With the help of Frida, we'll obtain the base image address in order to add the XOR instruction address to it and do all the operations to get the secret.

```javascript
Process.enumerateModules({
  onMatch: function(module){
    console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
    if (module.name=="libnative-lib.so"){
      var secret=""
      Interceptor.attach(module.base.add(0x06cf), function() {  
        var x = this.context.eax;
        var y = this.context.ecx;
        var z = x ^ y;
        secret+=String.fromCharCode(z)
        send(secret)  
      });     
    }
  }, 
  onComplete: function(){}
});
```

Below are the two secrets of this challenge (the two final ones of the overall challenge).

```txt
[SECRET5] Native_c0d3_1s_h4rd3r_To_r3vers3
[SECRET6] backd00r$Mu$tAlw4ysBeF0rb1dd3n$$
```
</a>
