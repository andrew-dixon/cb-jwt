# ColdBox JSON Web Tokens (JWT)

## Description

ColdBox Module for encoding and decoding [JSON Web Tokens (JWT)](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html). This is a port of the [CF-JWT-Simple](https://github.com/jsteinshouer/cf-jwt-simple) project which itself is a port of the node.js project [node-jwt-simple](https://github.com/hokaccha/node-jwt-simple) to CFML. It currently supports HmacSHA256, HmacSHA384, and HmacSHA512 signing algorithms.

## Usage

The module has three functions, encode, decode and verify.

```
jwt.encode( payload , key , [ algorithm ] );
jwt.decode( token , key , [ algorithm ] );
jwt.verify( token , key , [ algorithm ] );
```

Where the `payload` is a JSON string, the `key` is a string containing your encoding/decoding password, the `token` is a string containing the result of a previous JWT encoding and the optional `algorithm` value is one of HmacSHA256, HmacSHA384 or HmacSHA512 (default).

This could be used within a ColdBox security interceptor to create the JWT (encode), decode the JWT or verify the JWT is valid. When using it in an interceptor you need to declare the property using the lazy injector using the  `provider` keyword, e.g.:

```
property name="jwt" inject="provider:JWTService@jwt";
```