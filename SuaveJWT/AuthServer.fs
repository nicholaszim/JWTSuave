module AuthServer

open JwtToken
open Suave
open Suave.RequestErrors
open Suave.Filters
open SuaveJson
open Suave.Operators

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
}

let audienceWebPart config = 
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
    config.AddAudienceUrlPath |> path >=> POST >=> tryCreateAudience