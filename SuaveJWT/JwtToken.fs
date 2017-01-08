module JwtToken

open Encodings
open System
open System.Security.Claims
open System.IdentityModel.Tokens
open System.Security.Cryptography

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
    //getValidCredentials : string -> string -> Async<bool>
    getSecurityKey: Base64String -> SecurityKey
    getSigningCredentials : SecurityKey -> SigningCredentials
}

type Token = {
    AccessToken : string
    ExpiresIn : float
}

type TokenValidationRequest = {
    Issuer : string
    SecurityKey : SecurityKey
    ClientId : string
    AccessToken : string
}

let createToken request identityStore audience =
    async {
        let userName = request.UserName
        let! isValidCredentials = identityStore.isValidCredentials userName request.Password
        match isValidCredentials with
        | true -> 
            let (signingCredentials : SigningCredentials) = audience.Secret |> (identityStore.getSecurityKey >> identityStore.getSigningCredentials)
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

let validate validationRequest =
    let tokenValidationParameters =
        let validationParams = new TokenValidationParameters()
        validationParams.ValidAudience <- validationRequest.ClientId
        validationParams.ValidIssuer <- validationRequest.Issuer
        validationParams.ValidateLifetime <- true
        validationParams.ValidateIssuerSigningKey <- true
        validationParams.IssuerSigningKey <- validationRequest.SecurityKey
        validationParams
    try
        let handler = new JwtSecurityTokenHandler()
        let principal = handler.ValidateToken(validationRequest.AccessToken, tokenValidationParameters, ref null)
        principal.Claims |> Choice1Of2
    with
        | ex -> ex.Message |> Choice2Of2
