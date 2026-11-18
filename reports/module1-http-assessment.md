# Module 1 – HTTP Security Assessment

## Target
OWASP Juice Shop

## Target URL
http://127.0.0.1:3000

## Findings and observations

1. Port 3000 is open.
2. HTTP response status is 200 OK.
3. Application title: OWASP Juice Shop.
4. Access-Control-Allow-Origin is set to *.
5. HTTP OPTIONS request returns 204 No Content.
6. Allowed methods include GET, HEAD, PUT, PATCH, POST and DELETE.

## Preliminary Security Assessment

Wildcard CORS configuration requires further investigation.
No confirmed CORS vulnerability has been established.

## Environment
Kali Linux
Docker
Nmap
curl

## Status
Initial HTTP enumeration completed.

## CORS Investigation

Test origin: https://example.com

Observed:
- Access-Control-Allow-Origin: *
- Access-Control-Allow-Methods: GET, HEAD, PUT, PATCH, POST, DELETE
- Access-Control-Allow-Headers: Content-Type

Assessment:
The application accepts a wildcard origin in its CORS response.
This is a permissive cross-origin policy.

Impact:
Potential exposure depends on the resources available cross-origin,
authentication requirements, and credential handling.

Status:
Observation recorded. Exploitability not confirmed.

## CORS Test Results

Test origin: https://example.com

Results:
- HTTP status: 204 No Content
- Access-Control-Allow-Origin: *
- Access-Control-Allow-Methods: GET, HEAD, PUT, PATCH, POST, DELETE
- Access-Control-Allow-Headers: Content-Type
- Access-Control-Allow-Credentials: Not observed

Conclusion:
The application uses a permissive wildcard CORS policy.
Credentialed cross-origin access was not demonstrated.
No exploitable CORS vulnerability has been confirmed.
Further endpoint and authorization testing is required.
