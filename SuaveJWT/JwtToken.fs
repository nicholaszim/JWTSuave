module JwtToken

open System
open System.Security.Cryptography
open Encodings

type Audience = {
    ClientId: string
    Secret: Base64String
    Name: string
}

let createAudience audienceName =
    let clientId = Guid.NewGuid().ToString("N")
    let data = Array.zeroCreate 32
    RNGCryptoServiceProvider.Create().GetBytes(data)
    let secret = data |> Base64String.create
    { ClientId = clientId; Secret = secret; Name = audienceName }

