﻿module KeyStore
open System.IdentityModel.Tokens
open Encodings

let securityKey sharedKey : SecurityKey = 
    let symmetryKey = sharedKey |> Base64String.decode
    new InMemorySymmetricSecurityKey(symmetryKey) :> SecurityKey

let hmacSha256 secretKey =
    new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest)
