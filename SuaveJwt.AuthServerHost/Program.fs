open Suave

// Learn more about F# at http://fsharp.org
// See the 'F# Tutorial' project for more help.

[<EntryPoint>]
let main argv = 
    let authorizationServerConfig = {
        AddAudienceUrlPath = "/api/audience"
        SaveAudience = AudienceStorage.saveAudience
    }
    audienceWebPart authorizationServerConfig |> startWebServer dafaultConfig
