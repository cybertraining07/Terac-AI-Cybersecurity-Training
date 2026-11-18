
# Vulnerability Assessment Report

## Finding: Confidential Information Exposure Through Directory Listing

**Target:** OWASP Juice Shop
**Endpoint:** /ftp
**HTTP Method:** GET
**Vulnerability Category:** Security Misconfiguration
**CWE:** CWE-548
**Environment:** Authorized local Docker lab

### Description
The FTP directory is accessible without authentication and
returns a directory listing containing downloadable files.

During testing, the file acquisitions.md was retrieved.
The document was explicitly marked confidential and
described planned competitor acquisitions.

### Evidence
- GET /ftp returned HTTP 200.
- Directory listing exposed filenames.
- GET /ftp/acquisitions.md returned confidential business content.

### Potential Impact
Unauthorized disclosure of confidential business information,
which could affect business confidentiality and potentially
have financial or reputational consequences.

### Recommendation
- Disable directory indexing.
- Restrict access to sensitive directories.
- Store confidential documents outside publicly served directories.
- Enforce authentication and authorization.
- Review exposed backup and document files.
- Monitor access to sensitive resources.

### Status
Confirmed information disclosure in the authorized training lab.

### Evidence Files
- evidence/acquisitions.md
- evidence/gobuster-module1-final.txt
