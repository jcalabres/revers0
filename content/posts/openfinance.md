+++ 
title = "Open Banking and Mobile RE" 
date = "2024-04-05" 
author = "Joan Calabrés"  
description = "In this post I'll explain Mobile RE in open banking with a real example." 
+++

## What's Open Banking?

Open Banking is based on the principle that the data supplied by and created on behalf of banking services customers are owned and controlled by those customers. Re-use of this data by other providers takes place in a safe and ethical environment with informed consumer consent.

## Why Reverse Engineering?

In some countries exists some difficulties to access bank API's, most of them don't follow any standards and they have bad quality and stability. In addition, banks are not proactive to opening up their data to third parties.

For that reason, when there's not any posible partering with the banks or other alternatives, reverse engineering comes into place. Scraping data from websites and from mobile applications is commonly used to obtain all the data needed from the target API. 

## Why Mobile over Web?

There's no specific reason to chose one over the other. It's a decision that takes various factors and considerations:

* User experience - The API might be more limited for one of the options.
  * How many months of transactions we can get on Mobile over Web?
  * Is there any extra authentication mechanism on the Mobile version?
  * Do payments have any limitation? e.g. tokens needed, daily limits. 
* Reverse engineering difficulty - Depending on the obfuscation and the authentication mechanisms.
* Architecture and implementation costs - Do we have all the hardware and resources?

## Scraping APIs Process

The goals of scraping bank APIs should align with mirroring institutional functionalities, strategically employing methods to enhance user experience and circumvent UX obstacles like one-time passwords (OTPs) or cumbersome authentication processes. The common process involves:

1. Authentication and Login Procedures.
2. Data Scraping: Covering Transactions, Cards, Ownership Details...
3. Payment Services: Facilitating Local and International Transfers.

## Real World Example - Extracting Login API

On this example I'll analyze and extract the Login API of a Banking APP (Android). Some elements of this tutorial have been intentionally obscured or masked, primarily for educational purposes.

### Protection Techniques

The application uses the **MatrixHCE** payment SDK. This SDK is used for **HCE (Host Card Emulation)** payments and provides all the functionalities to perform secure payments, including the protection of the payment **(Visa/MasterCard)** assets such as the PAN (Personal Account Number), CVV, expiry date and cryptographic keys among other assets.

This payment SDK made by **Inside Secure** is one of the most advanced **HCE SDK's** in the market, it also provides state of the art software protections such as e.g. root detection, debug detection, hook detection, device binding, static and dynamic tampering protections and so on.


 Most of the times, these kind of SDK's only protects the payments assets, and it's responsability of the integrator app to implement their own protections or to integrate the SDK's protections correctly.

 The Inside Secure's SDK protections are mainly implemented in the native layer. The bank app loads the native library using the ```System.loadLibrary("hce_ndk");``` and uses the ```MatrixHCENativeBridge```class as a bridge between the Java and native layer. An example of the Inside Secure's implemented protections are:
 
```java
public static native MatrixHCE.RootingDetectionMethod getRootingDetectionMethod();
public static native MatrixHCE.RootingStatus getRootingStatus();
public static native boolean isAccountRegistered(String str);
public static native boolean isDeviceBindingStateInvalid();
public static native boolean isTampered();
public static native boolean issuerLoadLibrary(String str, String str2);
public static native boolean issuerUnloadLibrary(String str);
```

In addition the bank app has some environment protections at startup located inside the initial ```SplashActivity```. Furthermore, bank app has name mangling obfuscation in all the code including packages names and classes methods, flow obfuscation, string obfuscation and some protected classes that are unpacked only while the application is running, plus the benefits from the Inside Secure's protections.


### Techniques & Tools

I've used *Reverse Engineering* techniques that involves decompilation of Java code, hooking application functionalities and monitoring of the application's communications. The tools I have used are:

* [Jadx](https://github.com/skylot/jadx): Dex to Java decompiler.
* [Burp Suite Professional](https://portswigger.net/burp): Used to intercept network communications.
* [Magisk](https://github.com/topjohnwu/Magisk): Android super user framework.
* [Magisk for AVD](https://github.com/shakalaca/MagiskOnEmulator): Magisk for the Android Emulator.
* [AVD](https://developer.android.com/studio/run/emulator): The Android emulator.
* [Frida](https://frida.re): Hooking framework.
* [frida-dexdump](https://github.com/hluwa/frida-dexdump): Script to dump dex from memory.

###  Analysis of Network Traffic

The application uses certificate pinning with the backend server. I have used a **Frida** script to bypass this protection and analyze communications correctly. Sensitive information is encrypted and a negotiation of cryptographic keys is being made starting by the post request:

```json
POST /public/key HTTP/1.1
Host: *****
X-Appname: *****
X-Application-Key: *****
Firmware: 10
Platform: Android
App-Version: *****
Microservices: 1
Content-Type: application/json; charset=UTF-8
Content-Length: 868
Accept-Encoding: gzip, deflate
User-Agent: okhttp/3.4.0-RC1
Connection: close

{"clientPublicKey":"308201A3..."}
```

The server will respond with it's public key:

```json
HTTP/1.1 200 OK
signature: *****
content-type: application/json;charset=UTF-8
date: Sun, 08 May 2022 17:32:58 GMT
x-request-id: *****
cache-control: no-store, max-age=0
strict-transport-security: max-age=63072000; includeSubDomains
x-frame-options: DENY
x-xss-protection: 1; mode=block
x-download-options: noopen
x-content-type-options: nosniff
set-cookie: *****; Secure; HttpOnly; Domain=*****; Path=*****
vary: accept-encoding
Connection: close
Content-Length: 978

{"serverPublicKey":"308201A7...",
"appVersionStatus":"OK",
"serverDate":1652031178231}
```

The public key of the server will be used lately to send the generated AES key used to encrypt sensitive data.

### Encryption

The application uses a class for cryptographic operations that was packed and dumped while running. This class is the ```*****.dlcrypto.DLCrypto``` and contains multiple methods for encryption. The keys used for key exchange are generated in the method ```m6397``` and it's part of the **Diffie-Hellman** algorithm:

```java
SecureRandom secureRandom = new SecureRandom();
BigInteger probablePrime = BigInteger.probablePrime(1024, secureRandom);
BigInteger probablePrime2 = BigInteger.probablePrime(1024, secureRandom);
short s19 = (short) (C3269.m33() ^ 16016);
int[] iArr14 = new int["uz".length()];
C3255 r47 = new C3255("uz");
int i33 = 0;
while (r47.m44()) {
    int i34 = r47.m45();
    AbstractC3270 r214 = AbstractC3270.m27(i34);
    iArr14[i33] = r214.mo30(r214.mo28(i34) - (((s19 + s19) + s19) + i33));
    i33++;
    }
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(new String(iArr14, 0, i33));
keyPairGenerator.initialize(new DHParameterSpec(probablePrime, probablePrime2));
KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();
this.keyPair = generateKeyPair;
return OTgOVTlBcn.LfBjeUWJCY(generateKeyPair.getPublic().getEncoded());
```

After the generation of the DH and the first phase of the key exchange, the application will use an AES key to encrypt some data such as the username and password. All the crypto functionalities and encryption of the login process is happenning inside the ```DLCypto```class.

### Login API

Therefore the next requests to the server will have sensitive data encrypted, also the next request will check the username:

```json
POST /auth/customer HTTP/1.1
Host: *****
Cookie: *****
Signature: *****
X-Appname: *****
X-Application-Key: *****
Firmware: 10
Nonce: *****
Platform: Android
App-Version: *****
Microservices: 1
Timestamp: 1652031180118
Content-Type: application/json; charset=utf-8
User-Agent: Dalvik/2.1.0 (Linux; U; Android 10; Android SDK built for x86 Build/QSR1.190920.001)
Accept-Encoding: gzip, deflate
Content-Length: 268
Connection: close

{"app-version":"*****",
"cpf":username,
"cryptoSession":"*****",
"deviceName":"Google Android SDK built for x86",
"firmware":"10",
"imei":"*****",
"platform":"Android"}
```

The last phase for the login process will be the next request:

```json
POST /auth/login HTTP/1.1
Host: *****
Cookie: *****
Signature: *****
X-Appname: *****
X-Application-Key: *****
Hd: *****
Firmware: 10
Nonce: *****
Platform: Android
App-Version: *****
Microservices: 1
Timestamp: 1652033448943
Content-Type: application/json; charset=utf-8
User-Agent: Dalvik/2.1.0 (Linux; U; Android 10; Android SDK built for x86 Build/QSR1.190920.001)
Accept-Encoding: gzip, deflate
Content-Length: 2823
Connection: close

{"adaptiveAuthenticationResponse":"*****",
"appVersion":"*****",
"challengedone":false,
"checkMbb":true,
"cryptoSession":"*****",
"deviceDna":"*****",
"deviceName":"Google Android SDK built for x86",
"hasMbb":false,
"hasSeedApp":false,
"imei":"*****","keepLogged":false,
"loginType":"PASSWORD",
"password":password,
"passwordSize":4,
"username":username}
```

The request are mainly happening inside the classes ```LoginRequest```and ```UserClientRequest``` from the package ```*****.model.authentication```. An example of the data being encrypted is:

```Java
userClientRequest.setCryptoSession(OTgOVTlBcn.ZablFzHlxY().getSession());
userClientRequest.setCpf(OTgOVTlBcn.ZablFzHlxY().encrypt(userClientRequest.getCpf()));
userClientRequest.setImei(OTgOVTlBcn.ZablFzHlxY().encrypt(dVSABYIhhp.aQD9WmRC5e.vmx3eZC2Mw.fg8JPy
```

Now that we have the extracted Login API, we can implement the Login APIs and Crypto using Python.

## Conclusions

The process of scraping bank APIs involves replicating institutional functionalities while overcoming user experience challenges like one-time passwords and complex authentication methods. The standard procedure includes authentication, data scraping, and enabling payment services. A real-world example demonstrated extracting the Login API from a banking app, highlighting protection techniques, reverse engineering tools, network traffic analysis, encryption methods, and the extraction process. This facilitates understanding and implementing similar functionalities while emphasizing security and encryption in financial applications.