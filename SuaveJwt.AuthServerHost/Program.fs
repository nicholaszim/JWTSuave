open Suave
open AudienceStorage
open AuthServer
open System
open JwtToken

[<EntryPoint>]
let main argv = 
    let authorizationServerConfig = {
        AddAudienceUrlPath = "/api/audience"
        CreateTokenUrlPath = "/aoauth2/token"
        SaveAudience = AudienceStorage.saveAudience
        GetAudience = AudienceStorage.getAudience
        Issuer = "http://localhost:8083/suave"
        TokenTimeSpan = TimeSpan.FromMinutes(1.)
    }

    let identityStore = {
        getClaims = IdentityStore.getCleims
        isValidCredentials = IdentityStore.isValidCredentials
        getSecurityKey = KeyStore.securityKey
        getSigningCredentials = KeyStore.hmacSha256
    }
    let audienceWebPat' = audienceWebPart authrizationServerConfig identityStore
    startWebServer defaultConfig audienceWebPat'
    0
