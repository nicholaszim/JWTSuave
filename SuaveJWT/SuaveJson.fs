module SuaveJson
//open System.Encoding
open Suave
open Suave.Operators
open Suave.Successful
open Newtonsoft.Json
open Newtonsoft.Json.Serialization

let JSON v = 
        let settings = new JsonSerializerSettings()
        settings.ContractResolver
                <- CamelCasePropertyNamesContractResolver()
        let obj = JsonConvert.SerializeObject(v, settings)
        obj |> OK >=> Writers.setMimeType "application/json; charset=utf-8"

let mapJsonPayload<'a> (req : HttpRequest) =
    let fromJson json =
        try
            JsonConvert.DeserializeObject(json, typeof<'a>)
            :?> 'a
            |> Some
        with
        | _ -> None
    let getString =
        System.Text.Encoding.UTF8.GetString
    req.rawForm |> getString |> fromJson