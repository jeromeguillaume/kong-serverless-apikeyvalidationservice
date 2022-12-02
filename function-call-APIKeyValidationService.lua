-- Handle X-JWT-Assertion
-- Requirement: KONG_UNTRUSTED_LUA_SANDBOX_REQUIRES=resty.http,cjson.safe
return function ()
  
  -----------------------------------------------------------------------------------------------
  -- Extract Expiry value from Payload of JWT
  -- x_jwt_assertion is a classic JWT with 3 parts, separated by a dot: Header.Payload.Signature
  -----------------------------------------------------------------------------------------------
  local function extract_Expiry_JWT (x_jwt_assertion)
    local jwt_payload = ""
    -- Get 1st . (dot)
    local b4, e4 = string.find(x_jwt_assertion, "%.")
    local b5, e5
    -- Get 2nd . (dot)
    if e4 ~= nil then
      b5, e5 = string.find(x_jwt_assertion, "%.", e4 + 1)
    end
    -- If we failed to find JWT payload
    if e4 == nil or e5 == nil then
      kong.log.err ( "Failure to extract payload from 'X-JWT-Assertion'")
      return ""
    end
    
    jwt_payload = string.sub(x_jwt_assertion, e4 + 1, e5 - 1)
    
    -- bas64 decoding of JWT payload
    local decode_base64 = ngx.decode_base64
    local decoded = decode_base64(jwt_payload)
    local cjson = require("cjson.safe").new()
    local x_jwt_assertion_json, err = cjson.decode(decoded)
    -- If we failed to base64 decode
    if err then
      kong.log.err ( "Failure to decode base64 payload 'X-JWT-Assertion'")
      return ""
    end

    kong.log.notice ("X-JWT-Assertion.expiration=" .. x_jwt_assertion_json.exp)

    return x_jwt_assertion_json.exp
  end

  ---------------------------------------------------
  -- Call back function for call of 'kong.cache:get'
  ---------------------------------------------------
  local function to_be_cached (arg) 
      return arg
  end
  
  kong.log.notice ("BEGIN")
  
  local http = require "resty.http"
  local httpc = http.new()
  
  -- Retrieved Authorization Bearer from the Request
  local authorization_bearer = kong.request.get_header ("Authorization")
  local authorization_code = ""

  if authorization_bearer ~= nil then
    b1, e1 = string.find(string.lower(authorization_bearer), string.lower("Bearer "))
    
    if b1 ~= nil and e1 ~= nil then
      authorization_code = string.sub(authorization_bearer, e1 + 1, #authorization_bearer)
    end
  end
  
  if authorization_code == "" then
    return kong.response.exit(500, "{\
      \"Error Code\": " .. 500 .. ",\
      \"Error Message\": \"Kong function APIKeyValidationService: failure to retrieve 'Authorization Bearer'\"\
      }",
      {
      ["Content-Type"] = "application/json"
      }
    )
  end
  
  kong.log.notice ("authorization_bearer=" .. authorization_bearer)
  kong.log.notice ("authorization_code=" .. authorization_code)
  
  -- First, try to get the X-JWT-Assertion from cache linked with authorization_code
  local x_jwt_assertion, err = kong.cache:get(authorization_code)
  
  -- If there is an error getting cache (we log an error but we don't stop the call to Upstream srv)
  if err ~= nil then
    kong.log.err ( "An unexpected error occurred getting cache authorization_code: '" .. authorization_code .. 
      "', err: '" .. err .."'")
  -- If we succeeded to get authorization_code from Cache
  elseif x_jwt_assertion ~= nil then
    kong.service.request.add_header ("X-JWT-Assertion", x_jwt_assertion)
    kong.log.notice ("X-JWT-Assertion retrieved from cache=" .. x_jwt_assertion)
    return
  else
    kong.log.notice ("authorization_code not found in cache")
  end 

  -- Send the SOAP Request to the WSO2 IdP server to get Id Token (by using the Authorization Bearer)
  local body_soap = "<?xml version='1.0' encoding='UTF-8'?><soapenv:Envelope xmlns:soapenv=\"http://www.w3.org/2003/05/soap-envelope\"><soapenv:Body><ns6:validateKey xmlns:ns6=\"http://org.apache.axis2/xsd\"><ns6:context>/IDTokenGenerator/V1</ns6:context><ns6:version>V1</ns6:version>" ..
  "<ns6:accessToken>" .. authorization_code  .. "</ns6:accessToken>" ..
  "<ns6:requiredAuthenticationLevel>Any</ns6:requiredAuthenticationLevel><ns6:clientDomain xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"1\"/><ns6:matchingResource>/idTokens</ns6:matchingResource><ns6:httpVerb>POST</ns6:httpVerb></ns6:validateKey></soapenv:Body></soapenv:Envelope>"

  kong.log.notice ("request.body=" .. body_soap)
  
  local res, err = httpc:request_uri("http:/<wso2-idp-server>:8080/services/APIKeyValidationService", {  
    method = "POST",
    headers = {
      ["Content-Type"] = "application/soap+xml",
      ["action"] = "urn:validateKey",
      ["Authorization"] = "Basic <*** change-me ***>",
    },
    query = { 
    },
    body = body_soap,
    keepalive_timeout = 60,
    keepalive_pool = 10
    })
    
  if err then
    kong.log.err ("err=" .. err)
      return kong.response.exit(500, "{\
      \"Error Code\": " .. 500 .. ",\
      \"Error Message\": \"Kong function APIKeyValidationService: Unable to call correctly the IdP Endpoint\"\
      }",
      {
      ["Content-Type"] = "application/json"
      }
    )
    -- return nil, err
  end
  
  kong.log.notice ("response.body=" .. res.body)
  
  if res.status ~= 200 then
      return kong.response.exit(res.status, "{\
      \"Error Code\": " .. res.status .. ",\
      \"Error Message\": \"Kong function APIKeyValidationService: Unable to call correctly the IdP Endpoint\"\
      }",
      {
      ["Content-Type"] = "application/json"
      }
    )
  end

  -- Extract the X-JWT-Assertion
  x_jwt_assertion = ""
  local b2, e2 = string.find(res.body, "<ax232:endUserToken>")
  local b3, e3 = string.find(res.body, "</ax232:endUserToken>")
  if e2 ~= nil and b3 ~= nil then
    x_jwt_assertion = string.sub(res.body, e2 + 1, b3 - 1)
  end
  
  if x_jwt_assertion == "" then
    return kong.response.exit(500, "{\
    \"Error Code\": " .. 500 .. ",\
    \"Error Message\": \"Kong function APIKeyValidationService: failure to retrieve 'X-JWT-Assertion' from IdP response\"\
    }",
    {
    ["Content-Type"] = "application/json"
    }
  )
  end

  -- Extract Expiry value from JWT
  local exp = extract_Expiry_JWT (x_jwt_assertion)

  -- if Expiry value is found
  if exp ~= "" then
    kong.log.notice("X-JWT-Assertion.expiration=".. os.date('%d/%m/%Y %X', tonumber(exp)))

    -- Calculate the TTL (Time To Live) of duration cache
    ttl_x_jwt_assertion = tonumber(exp) - ngx.time()
    if ttl_x_jwt_assertion <= 0 then
      kong.log.err ( "Failure setting cache for authorization_code / X-JWT-Assertion, invalid TTL: " .. ttl_x_jwt_assertion)
    else
      -- Set X-JWT-Assertion in cache
      local res, err = kong.cache:get(authorization_code, {ttl = ttl_x_jwt_assertion}, to_be_cached, x_jwt_assertion)
      if err then
        kong.log.err ( "An unexpected error occurred setting cache for authorization_code / X-JWT-Assertion, err: '" .. err .."'")
      else
        kong.log.notice ( "authorization_code: '" .. authorization_code ..  "' is set successfully in cache with TTL: '" .. ttl_x_jwt_assertion .. "' and value '" .. x_jwt_assertion .. "'")
      end
    end
  else
    kong.log.err ( "Failure setting cache for authorization_code / X-JWT-Assertion, expiration was not processed correctly")
  end

  -- Add the X-JWT-Assertion in Header
  kong.service.request.add_header ("X-JWT-Assertion", x_jwt_assertion)
  kong.log.notice ("X-JWT-Assertion=" .. x_jwt_assertion)

  kong.log.notice ("END")
end