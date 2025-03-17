# spring-security-6-upgrade
This project includes oauth2-authorization-server:1.5.0-M1 and resource server config with opaque token 

required /.gradle dependencies

	implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
	implementation 'org.springframework.boot:spring-boot-starter-web'
	implementation 'org.springframework.boot:spring-boot-starter-oauth2-authorization-server'
	implementation 'org.springframework.security:spring-security-oauth2-authorization-server:1.5.0-M1'
	implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
	implementation 'org.springframework.security:spring-security-oauth2-client'
	implementation 'org.springframework.security:spring-security-oauth2-core'
	implementation 'org.springframework.security:spring-security-oauth2-jose:6.4.3'
	implementation 'org.springframework.boot:spring-boot-starter-security'
	implementation 'org.springframework.security:spring-security-web'
	implementation 'org.springframework.boot:spring-boot-starter-validation'

Auth2Token Generate Curl.

    curl --location 'http://localhost:8080/oauth/token' \
    --header 'app_version: 2.2.1' \
    --header 'check_sum: fdfe13d50cc583494b0bcd54861b89449ecc2337b3f763041f8334ccbd57d167' \
    --header 'Content-Type: application/json' \
    --header 'Cookie: JSESSIONID=E97796DC701B36AC24B7F33510580B8A' \
    --data '{
      "grant_type": "password",
      "client_id": "mobile_api_client",
      "auth_type": "pin",
      "one_signal_id": "12321389289823802442",
      "request_token": "15140a97-ce76-4099-8e83-602dcdb33d4e",
      "pin": "12345",
      "client_secret": "6f6b8a16-e356-4850-bdde-423d36321940",
      "device_id": "43fe7c0dfeaa73afg",
      "platform":"android"
    }'

Sample Response

    {
        "access_token": "a9eaab1b-f444-43a9-8953-1ac71588b546",
        "token_type": "bearer",
        "refresh_token": "277a7b3e-1129-4c12-8c64-d0f0fb35f766",
        "expires_in": 3600,
        "scope": "read"
    }


Sample Curl request to test secure API
    
    curl --location 'http://localhost:8080/oauth/check' \
    --header 'Authorization: Bearer b1f01a84-ddd2-4b9d-b545-552407374006' \
    --header 'Cookie: JSESSIONID=E97796DC701B36AC24B7F33510580B8A'


Generate base 64 token for introspect - echo -n "mobile_api_client:6f6b8a16-e356-4850-bdde-423d36321940" | base64
      
Test Introspect  

    curl --location 'http://localhost:8080/oauth/introspect' \
    --header 'Authorization: Bearer 685b72d2-48ff-4ffe-a566-6251f75b4523' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --header 'Cookie: JSESSIONID=72A72E3DDBCBCC7680F27BA655678727' \
    --data-urlencode 'token=a9eaab1b-f444-43a9-8953-1ac71588b546'


Introspect response 

    {
    "sub": "755783205",
    "exp": 1742202579,
    "scope": "read write",
    "roles": [
        "ROLE_MOBILE_APP_USER"
    ],
    "active": true
  }
