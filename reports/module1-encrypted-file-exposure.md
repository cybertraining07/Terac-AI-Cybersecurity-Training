# Security Finding: Encrypted File Exposure

## Target
OWASP Juice Shop - Authorized Local Lab

## Endpoint
/ftp/announcement_encrypted.md

## Finding
Unauthenticated access to an encrypted announcement file.

## Evidence
- The /ftp directory listing is accessible without authentication.
- announcement_encrypted.md appears in the directory listing.
- The file can be retrieved through an HTTP GET request.
- The retrieved content consists of large numerical ciphertext values.

## Potential Impact
The exposure reveals the existence and contents of an encrypted file.
The confidentiality impact depends on the encryption implementation,
key management, and sensitivity of the original information.

## Recommendation
- Restrict access to sensitive files.
- Disable public directory listing.
- Store sensitive documents outside publicly accessible directories.
- Review encryption and key-management practices.
- Remove unnecessary files from web-accessible locations.

## Status
Confirmed file exposure. Encryption strength and plaintext sensitivity
not assessed.
