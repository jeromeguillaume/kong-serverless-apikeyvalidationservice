# API Key Validation Service: Kong Servless function
This Kong Servless function calls a SOAP request on WSO2 IdP.
It retrieves an opaque acess token (from Authorization: Bearer header) and it gets back a JWT from IdP.

## How deploy this Kong Function?
1) Modify the SOAP URL of the IdP server, see Lua command: ```httpc:request_uri("http:/<wso2-idp-server>:8080/services/...```)
2) Modify the ```["Authorization"] = "Basic <*** change-me ***>"``` value
3) Deploy the Kong servless function
```
curl -i -X POST http://<kong-admin-api>:8001/<my-service>/plugins \
     -F "name=post-function" \
     -F "config.access[1]=@function-call-APIKeyValidationService.lua" \
     -H "Kong-Admin-Token: <to-be-changed>"
```