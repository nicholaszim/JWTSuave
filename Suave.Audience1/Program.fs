open Suave
open Suave.Http
open Suave.Web
open Secure
open Encodings
open System.Security.Claims
open Suave.Successful
open Suave.Filters
open Suave.Operators

[<EntryPoint>]
let main argv =
        let base64Key = 
                Base64String.fromString "Op5EqjC70aLS2dx3gI0zADPIZGX2As6UEwjA4oyBjMo"
        let jwtConfig = {
                Issuer = "http://localhost:8083/suave"
                ClientId = "7ff79ba3305c4e4f9d0ececeae70c78f"
                SecurityKey = KeyStore.securityKey base64Key
        }
        let sample1 = 
                path "/audience1/sample1" 
                >=> jwtAuthenticate jwtConfig (OK "Sample 1")
        let config = 
                { defaultConfig 
                                with bindings = [Suave.Http.HttpBinding.createSimple HTTP "127.0.0.1" 8084]}
        startWebServer config sample1
        0
