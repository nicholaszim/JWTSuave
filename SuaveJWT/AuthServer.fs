module AuthServer

open JwtToken
open Suave
open Suave.RequestErrors
open Suave.Filters
open SuaveJson
open Suave.Operators
open System

type AudienceCreateRequest = {
    Name : string
}

type AudienceCreateResponse = {
    ClientId : string
    BaseSecret : string
    Name : string
}
type Config = {
    AddAudienceUrlPath : string
    SaveAudience : Audience -> Async<Audience>

    CreateTokenUrlPath: string
    GetAudience: string -> Async<Audience option>
    Issuer: string
    TokenTimeSpan: TimeSpan
}

type TokenCreateCredentials = {
    UserName: string
    Password: string
    ClientId: string
}


let audienceWebPart config identityStore = 
    let toAudienceCreateResponse (audience : Audience) = {
        BaseSecret = audience.Secret.ToString()
        ClientId = audience.ClientId
        Name = audience.Name
    }

    let tryCreateAudience (ctx: HttpContext) =
        match mapJsonPayload<AudienceCreateRequest> ctx.request with
        | Some audienceCreateRequest ->
            async {
                let! audience = 
                    audienceCreateRequest.Name
                    |> createAudience
                    |> config.SaveAudience
                let audienceCreateResponse =
                    toAudienceCreateResponse audience
                return! JSON audienceCreateResponse ctx
            }
        | None -> BAD_REQUEST "Invalid Audience Create Request" ctx


    let tryCreateToken (ctx: HttpContext) = 
        match mapJsonPayload<TokenCreateCredentials> ctx.request with
        | Some tokenCreateCredentials -> 
            async {
                let! audience = config.GetAudience tokenCreateCredentials.ClientId
                match audience with
                | Some audience ->
                    let tokenCreateRequest : TokenCreateRequest = {
                        Issuer = config.Issuer
                        UserName = tokenCreateCredentials.UserName
                        Password = tokenCreateCredentials.Password
                        TokenTimeSpan = config.TokenTimeSpan
                    }
                    let! token = createToken tokenCreateRequest identityStore audience
                    match token with
                    | Some token -> return! JSON token ctx
                    | None -> return! BAD_REQUEST "Invalid Login Credentials" ctx
                | None -> return! BAD_REQUEST "Invalid Token Create Request" ctx
            }
        | None -> BAD_REQUEST "Invalid Login Credentials" ctx
    
    choose [
        path config.AddAudienceUrlPath >=> POST >=> tryCreateAudience
        path config.CreateTokenUrlPath >=> POST >=> tryCreateToken
    ]