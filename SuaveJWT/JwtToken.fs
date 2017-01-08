module JwtToken

open System
open System.Security.Cryptography
open Encodings
open System.IdentityModel.Tokens.Jwt
open System.Security.Claims
open Microsoft.IdentityModel.Tokens

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

type TokenCreateRequest = {
    Issuer : string
    UserName : string
    Password : string
    TokenTimeSpan : TimeSpan
}

type IdentityStore = {
    getClaims: string -> Async<Claim seq>
    isValidCredentials: string -> string -> Async<bool>
    getValidCredentials : string -> string -> Async<bool>
    getSecurityKey: Base64String -> SecurityKey
    getSigningCredentials : SecurityKey -> Microsoft.IdentityModel.Tokens.SigningCredentials
}

type Token = {
    AccessToken : string
    ExpiresIn : float
}

let createToken request identityStore audience =
    async {
        let userName = request.UserName
        let! isValidCredentials = identityStore.isValidCredentials userName request.Password
        match isValidCredentials with
        | true -> 
            let (signingCredentials : Microsoft.IdentityModel.Tokens.SigningCredentials) = audience.Secret |> (identityStore.getSecurityKey >> identityStore.getSigningCredentials)
            let issuedOn = Nullable DateTime.UtcNow
            let expiresBy = Nullable (DateTime.UtcNow.Add(request.TokenTimeSpan))
            let! claims = identityStore.getClaims userName
            let jwtSecurityToken = new JwtSecurityToken(request.Issuer, audience.ClientId, claims, issuedOn, expiresBy, signingCredentials)
            let handler = new JwtSecurityTokenHandler()
            let accessToken = handler.WriteToken(jwtSecurityToken)
            return Some { AccessToken = accessToken; 
                            ExpiresIn = request.TokenTimeSpan.TotalSeconds}
        | false ->
            return None
    }

