# JWTComponents

[![Build Status](https://github.com/couchdeveloper/JWTComponents/workflows/Build/badge.svg?branch=main)](https://github.com/couchdeveloper/JWTComponents/actions) [![GitHub license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0) [![Swift 5.3](https://img.shields.io/badge/Swift-5.3-orange.svg?style=flat)](https://developer.apple.com/swift/) ![Platforms macOS 10.15+ | Mac Catalyst 13.0+ | iOS 13+ | tvOS 13.0+ | watchOS 6.0+ | Linux ](https://img.shields.io/badge/Platform-macOS%2010.15%2B%20%7C%20Mac%20Catalyst%2013.0%2B%20%7C%20iOS%2013%2B%20%7C%20tvOS%2013.0%2B%20%7C%20watchOS%206.0%2B%20%7C%20Linux%20-brightgreen)

## Overview

JWTComponents is an easy to use library for composing and verifying [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519). On Apple platforms it's based on Apple's new CryptoKit library. For other platforms it uses [swift-crypto](https://github.com/apple/swift-crypto) as the underlying crypto framework.

**JWTComponents is still Work in Progress!**


**Caveats:**
- Does currently not support JWE
- Does not support crypto algorithms based on RSA.
- Windows not yet supported

**Contributors are wellcome!**

### JWS supported algorithms:
  - HS256
  - HS384
  - HS512
  - ES256
  - ES384
  - ES512

### Supported Platforms:
- macOS 10.15+
- Mac Catalyst 13.0+
- iOS 13+
- tvOS 13.0+
- watchOS 6.0+
- Linux (tested on Ubuntu)

## Install
via SPM

## Usage Examples
### Compose a JWT

You start off with a `JWTComponents` variable and specify claims and JOSE header parameters:

```Swift
#import JWTComponents

var jwtc = JWTComponents()
jwtc.issuer = "com.mycompany"
jwtc.subject = "OIDC-client"
jwtc.setValue("HS256", forHeaderParameter: .alg)
```

There are corresponding properties for standard claims, but you can set any custom claim value or any JOSE parameter whose type is JSON encodable:
```Swift
jwtc.setValue(["value1", "value2"], forClaim: "myClaim")
jwtc.setValue("HS256", forHeaderParameter: .alg)
```
Some claims can either contain a single value or an array of values, the `aud` (audience) claim for example.
This is how we can set a single value:

```Swift
jwtc.audience = "myaudience"
```
This is how we can set multiple values:
```Swift
jwtc.audience = ["myaudience1", "myaudience2"]
```
Note that claim values may have certain requirements regarding syntax and `JWTComponents` is very picky about this. For example, the "audience" value must be either a single value of a `StringOrURI`, or an array of `StringOrURI`. The setter checks if the value or values conform to `StringOrURI`. When trying to set a claim value which is not a valid `StringOrURI` value - and since a setter cannot throw errors, a fatal error will occur.

When finished composing the JWT, we want to add a signature. What we need for this is a "Signer" and a secret or key to parameterise the signing.

Since we already specified the signing algorithm (HS256 ) with the JOSE parameter `alg`,  JWTComponents will try to find this signer automatically. We only need to specify the key:

```Swift
try jwtc.sign(withKey: myStrongSecret)
```
> Caution: Always use _strong_ secrets and _strong_ keys!


When this was successful, we obtain the JWT in the JSON Compact Serialization form:
```Swift
let jwt = try jwtc.jwtCompact()
```

Printing the value `jwt` to the console prints out the signed JWT (line breaks inserted for better readability):

    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.
    eyJzdWIiOiJPSURDLWNsaWVudCIsImlzcyI6ImNvbS5teWNvbXBhbnkifQ.
    IOcoKqAhUYITjmWjjCK-hNGOvm9Wo8JhRbp6xZ7S8gs

For debugging purpose printing the `JWTComponents` value to the console outputs a more readable version of the JWT:
```Console
{
  "typ" : "JWT",
  "alg" : "HS256"
}.
{
  "sub" : "OIDC-client",
  "iss" : "com.mycompany"
}.
IOcoKqAhUYITjmWjjCK-hNGOvm9Wo8JhRbp6xZ7S8gs

```

> **Note:**
As we can see, the JOSE header parameter `typ` has been automatically inserted when the JWT has been signed.


### Verify a JWT

Verifying a JWT checks if the JWT is wellformed and if the signature is valid.

Given a JWT - which is a  JWS in "JWS Compact Serialization" format: 
```
let jws = ewogICJhbGciOiAiRVMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJzdWIiOiAiMTIzNDU2Nzg5MCIsCiAgIm5hbWUiOiAiSm9obiBEb2UiLAogICJpYXQiOiAxNTE2MjM5MDIyCn0.rrpQhPNCG5_Kf7tyzrd25D7I0GK4aYO_NPqmtM8i8NJR1FLj_dt4G7FpM5xwAaZyXuDzguhKHupoABpHYVRNxQ
```
Note, that this is a different one as above. So, we use `JWTComponets` to get a glimpse what's in there:
```Swift
#import JWTComponents

let jwtc = JWTComponets(jws: jws)
print(jwtc)
```

It prints out this to the console:
```console
{
  "alg" : "ES256",
  "typ" : "JWT"
}.
{
  "name" : "John Doe",
  "sub" : "1234567890",
  "iat" : 1516239022
}.
rrpQhPNCG5_Kf7tyzrd25D7I0GK4aYO_NPqmtM8i8NJR1FLj_dt4G7FpM5xwAaZyXuDzguhKHupoABpHYVRNxQ
```

As we can see, this is a JWS signed with ES256 which uses public-key cryptography to sign and verify the content. Let's assume, the given JWS is valid regarding the signing algorithm and we know the _public_ key and have it in its raw representation (a Data value).

Let's try to verify it:

```Swift
let secret: Data = ...
let verifier = try JWTFactory.createJWTVerifier(algorithm: .ES256, keyData: secret)
try jwtc.verify(with: verifier)
```

We create a verifier with a known algorithm (ES256) and the known secret. Then we verify the JWS with the verifier. If the JWS is valid, the function will simply succeed.

Otherwise, if the JWS is not valid, for example, if the JWS has been tampered with, function `verify(with:)` will fail. Printing the error to the console will show this:

```console
JWTComponents.verify(with:) failed: ES256_JWTVerifier.verify(message:signature:) failed: JWT signature verification with algorithm ES256 failed
```

## Validation

 ```Swift
 #import JWTComponents

 let jwtc = JWTComponets(jws: jws)
 try jwtc.validate()

 try jwtc.validate(forHeader: JOSEHeader.self,
                   claims: RegisteredClaims.self) { header, claims in
     try assertEqual(header.alg, "HS256")
     try assertEqual(header.typ, "JWT")
     try assertEqual(claims.issuer, "com.couchdeveloper")
     try assertEqual(claims.audience, "test")
 }


```
### Conveniently Verfiy Signature and Validate Claims and Header

```Swift
let verifier = try JWTFactory.createJWTVerifier(algorithm: .HS256, keyData: keyData)
try jwtc.validate(with: verifier,
                  forHeader: JOSEHeader.self,
                  claims: RegisteredClaims.self) { header, claims in
    try assertEqual(header.alg, "HS256")
    try assertEqual(header.typ, "JWT")
    try assertEqual(claims.issuer, "com.couchdeveloper")
    try assertEqual(claims.audience, "test")
}
```
