# AssessmentQuestions.md — RNG-EXT-01 · SETU DVAAR
## OPERATION DEEPSTRIKE | Assessment & Scoring Questions

**Instructions:** Answer these questions to demonstrate understanding of each vulnerability and the attack chain. Questions are ordered by machine (M1–M5). Answers validated against scoring keys in TTP YAML files.

---

## M1 — JWT Algorithm Confusion (20 points)

**Q1 [2pts]** What URL exposes the server's RSA public key, and in what format is it returned?

**Q2 [3pts]** Explain why a server that uses RS256 for JWT signing is vulnerable when it also accepts HS256 tokens. What is the specific condition in PyJWT 1.7.1 that enables this?

**Q3 [5pts]** Write the Python snippet that converts a JWK `n` and `e` value to a PEM-encoded RSA public key.

**Q4 [5pts]** What is the exact value of `graphql_api_key` returned by the admin system-config API after successful exploitation? (Scored against flag)

**Q5 [5pts]** What is the single line change to the `verify_token()` function that would completely prevent this attack? Explain why your fix works.

---

## M2 — GraphQL AuthZ Bypass (20 points)

**Q6 [3pts]** GraphQL introspection is disabled. What alternative technique allows schema enumeration, and what library feature enables it?

**Q7 [4pts]** You query `{ batchQueery(queries:["test"]) { key data } }` and get an error. What does the error tell you, and what is the correct query?

**Q8 [5pts]** What is the plaintext password for user `rpal-tariff-svc` extracted via the batchQuery vulnerability? (Scored against flag)

**Q9 [4pts]** What is the root cause of the batchQuery vulnerability? What single line of Python code, if added, would fix it?

**Q10 [4pts]** A blue teamer is reviewing GraphQL access logs. Write a Splunk query to detect schema enumeration via field suggestions from a single IP.

---

## M3 — XXE → SSRF → IMDS (20 points)

**Q11 [3pts]** What three lxml parser settings create the XXE vulnerability? Write the vulnerable parser instantiation.

**Q12 [5pts]** Write a complete SOAP request (including WS-Security headers) that uses an XXE external entity to fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.

**Q13 [4pts]** What IAM role name does the IMDS return when you enumerate `/latest/meta-data/iam/security-credentials/`?

**Q14 [4pts]** What internal API endpoint is revealed in the `_rpal_endpoint` field of the IMDS credential response?

**Q15 [4pts]** What iptables rule would permanently block the application process from reaching the IMDS endpoint at 169.254.169.254?

---

## M4 — HTTP Request Smuggling (20 points)

**Q16 [4pts]** Explain the CL.TE desync: what does HAProxy do with `Content-Length` vs `Transfer-Encoding`, and what does Gunicorn do?

**Q17 [5pts]** A smuggled request must have specific Content-Length value. If your smuggled prefix (after the zero-chunk) is 60 bytes, what must the Content-Length header value be? Show your calculation.

**Q18 [5pts]** What is the captured Bearer token format? Describe the algorithm used to generate it (seed, window, hash function).

**Q19 [3pts]** What endpoint do you call with the captured token, and what credentials does it return?

**Q20 [3pts]** What HAProxy configuration directive, added to the frontend section, would eliminate the CL.TE vulnerability?

---

## M5 — wkhtmltopdf SSRF (20 points)

**Q21 [3pts]** What field in the contractor application form is the SSRF injection point? What is the legitimate intended use of this field?

**Q22 [4pts]** Write the URL-encoded form data for a POST to `/apply` that reads `/etc/rpal/upstream/config.ini`.

**Q23 [4pts]** What are the two wkhtmltopdf command-line flags that enable file:// protocol access? Which version of wkhtmltopdf first disabled this by default?

**Q24 [5pts]** What is the SSH passphrase for the `svc-deploy` private key extracted from config.ini? (Scored against flag)

**Q25 [4pts]** A developer asks how to keep the PDF profile feature but prevent SSRF. Write the Python `validate_profile_url()` function that allows only http/https from non-private IPs.

---

## Scoring Summary

| Section | Max Points | Your Score |
|---|---|---|
| M1 JWT Confusion | 20 | |
| M2 GraphQL AuthZ | 20 | |
| M3 XXE SSRF IMDS | 20 | |
| M4 HTTP Smuggling | 20 | |
| M5 wkhtmltopdf SSRF | 20 | |
| **Total** | **100** | |

Passing score: 70/100 | Distinction: 90/100

---
*AssessmentQuestions.md | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
