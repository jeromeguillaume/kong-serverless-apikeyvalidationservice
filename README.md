# API Key Validation Service: Kong Serverless Function
This Kong Servless Function calls a SOAP request on WSO2 IdP to get a JWT.

## How does the Kong Function work?
- Retrieve an opaque acess token from the header request ```Authorization: Bearer``` of the Consumer
- Send a SOAP request on WSO2 IdP and get back a JWT
- Add the JWT in ```X-JWT-Assertion``` Upstream request header

## How deploy this Kong Function?
1) Modify the SOAP URL of the IdP server, see Lua command: ```httpc:request_uri("http:/<wso2-idp-server>:8080/services/...```)
2) Modify the ```["Authorization"] = "Basic <*** change-me ***>"``` value
3) Deploy the Kong serverless function
```
curl -i -X POST http://<kong-admin-api>:8001/<my-service>/plugins \
     -F "name=post-function" \
     -F "config.access[1]=@function-call-APIKeyValidationService.lua" \
     -H "Kong-Admin-Token: <to-be-changed>"
```