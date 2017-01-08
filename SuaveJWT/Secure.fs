﻿module Secure

open System.Security.Claims

open System.IdentityModel.Tokens
open JwtToken
open Suave
open Suave.RequestErrors

type JwtConfig = {
    Issuer : string
    SecurityKey : System.IdentityModel.Tokens.SecurityKey
    ClientId : string
}

let jwtAuthenticate jwtConfig webpart (ctx: HttpContext) =
    let updateContextWithClaims claims =
        {
            ctx with userState = ctx.userState.Remove("Claims").Add("Claims", claims)
        }
    match ctx.request.header "token" with
    | Choice1Of2 accessToken ->
        let tokenValidationRequest = {
            Issuer = jwtConfig.Issuer
            SecurityKey = jwtConfig.SecurityKey
            ClientId = jwtConfig.ClientId
            AccessToken = accessToken
        }
        let validationResult = validate tokenValidationRequest
        match validationResult with
        | Choice1Of2 claims -> webpart (updateContextWithClaims claims)
        | Choice2Of2 err -> FORBIDDEN err ctx
    | _ -> BAD_REQUEST "Invalid Request. Provide both clientid and token" ctx