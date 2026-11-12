# Static Security Findings Summary

## 1. Summary of Security Findings

| **ID** | **Title** | **Affected Location** | **Risk / Impact** |
|---|---|---|---|
| **SEC-01** | Path Traversal (Arbitrary File Read) | `download_file()`, lines 150–154 | Unauthorized read of arbitrary system files accessible to the process. |
| **SEC-02** | Broken Object Level Authorization (BOLA) | `get_profile()` / `get_grades()`, lines 128–140 | Unauthorized access to sensitive student profiles and grade records. |
| **SEC-03** | Missing Authentication & Authorization on Grade Updates | `update_grade()`, lines 142–153 | Unauthorized creation or modification of student grades by unauthenticated actors. |
| **SEC-04** | Hardcoded Predictable Flask Secret Key | Line 7 (`app.config["SECRET_KEY"]`) | Session forging and privilege escalation via signed cookie manipulation. |
| **SEC-05** | Verbose Error Handling and Debug Mode Enabled | Lines 156–166 | Information disclosure via exception messages and stack traces. |

---

## 2. Detailed Findings & Supporting Explanations

### SEC-01: Path Traversal (Arbitrary File Read)

**1. Identifier and Title:**  
SEC-01 - Path Traversal in File Download Endpoint.

**2. Affected Location:**  
File `baseline_secure_coding_api.py`, function `download_file()`, lines 150–154.

**3. Attacker Input & Data-Flow Path:**

The attacker supplies an arbitrary string via the `path` query parameter:

```python
raw_path = flask.request.args.get("path", "")
```

This input is concatenated directly onto `MATERIALS_DIR` using `pathlib.Path` division:

```python
target = MATERIALS_DIR / raw_path
```

The resulting path is then passed directly to:

```python
flask.send_file(target)
```

**4. Missing Control & Root Cause:**

The application lacks input sanitization and boundary validation. The root cause is trusting raw user input to construct filesystem paths without verifying that the resolved target remains within `MATERIALS_DIR`.

**5. Preconditions & Impact:**

- **Preconditions:** The application must be running and accessible.
- **Impact:** An attacker can read sensitive files outside the intended materials directory (e.g., `/etc/passwd` or application source code) using directory traversal sequences such as:

```text
?path=../../../../etc/passwd
```

**6. Proposed Test:**

Send an HTTP GET request to:

```http
GET /files?path=../../../../etc/passwd
```

A successful confirmation returns the contents of the password file or application source code rather than a 404/error response.

**7. Assumptions & Confidence:**

Assumes the web server process has read permissions for target files.

**Confidence:** High, based on direct code inspection.

---

### SEC-02: Broken Object Level Authorization (BOLA) on Student Data

**1. Identifier and Title:**  
SEC-02 - Broken Object Level Authorization (BOLA) for Student Profiles and Grades.

**2. Affected Location:**  
File `baseline_secure_coding_api.py`, functions:

- `get_profile()` (lines 128–134).
- `get_grades()` (lines 136–140).

**3. Attacker Input & Data-Flow Path:**

The attacker supplies arbitrary `student_id` path parameters.

The functions parse the integer ID and query `STUDENT_PROFILES` or `GRADES` directly without inspecting `flask.session` to verify identity or permissions.

**4. Missing Control & Root Cause:**

Absence of access control checks.

The application assumes that knowing or guessing a numeric student identifier grants authorization to view that student's records.

**5. Preconditions & Impact:**

- **Preconditions:** Valid student IDs must be known or enumerated (e.g., sequential IDs starting at 1001).
- **Impact:** Any user, authenticated or unauthenticated, can view any student's personal profile (email, name, program) and academic grades.

**6. Proposed Test:**

Without logging in, send the following HTTP GET requests:

```http
GET /students/1001/profile
GET /grades/1001
```

If JSON data is returned successfully, the vulnerability is confirmed.

**7. Assumptions & Confidence:**

Assumes students should only view their own records, while professors and administrators should have restricted access according to their roles.

**Confidence:** High.

---

### SEC-03: Missing Authentication & Authorization on Grade Updates

**1. Identifier and Title:**  
SEC-03 - Missing Authentication and Authorization on Grade Updates.

**2. Affected Location:**  
File `baseline_secure_coding_api.py`, function `update_grade()`, lines 142–153.

**3. Attacker Input & Data-Flow Path:**

The attacker sends a POST request with a JSON payload containing:

- `student_id`
- `course_id`
- `grade`

The endpoint immediately modifies or appends to the global `GRADES` list without verifying session state.

**4. Missing Control & Root Cause:**

Neither session authentication checks:

```python
if "user" not in flask.session:
```

nor role-based authorization checks (verifying whether the user is a professor assigned to the course or an administrator) are implemented.

**5. Preconditions & Impact:**

- **Preconditions:** Network reachability to the REST API.
- **Impact:** Unauthenticated attackers can tamper with academic records, falsifying grades or inserting arbitrary grade entries.

**6. Proposed Test:**

Send a POST request to `/grades/update` with the following JSON body, without establishing a session cookie:

```http
POST /grades/update
Content-Type: application/json
```

```json
{
    "student_id": 1001,
    "course_id": "SRS",
    "grade": 20
}
```

A `200 OK` response confirming the update proves the vulnerability.

**7. Assumptions & Confidence:**

Assumes grade updates require administrative or professor privileges.

**Confidence:** High.

---

### SEC-04: Hardcoded Predictable Flask Secret Key

**1. Identifier and Title:**  
SEC-04 - Hardcoded Secret Key Enabling Session Forgery.

**2. Affected Location:**  
File `baseline_secure_coding_api.py`, line 7:

```python
app.config["SECRET_KEY"] = "dev-secret-key"
```

**3. Attacker Input & Data-Flow Path:**

Flask signs client-side session cookies using `SECRET_KEY`.

Because the key is hardcoded and publicly visible in the source code, an attacker can craft valid signed session cookies.

**4. Missing Control & Root Cause:**

Use of a static, well-known development secret key in the application code.

**5. Preconditions & Impact:**

- **Preconditions:** Knowledge of the hardcoded secret key (`dev-secret-key`).
- **Impact:** An attacker can forge a session cookie asserting arbitrary roles and user attributes (e.g., setting `role: "admin"` or `role: "professor"`), potentially achieving complete privilege escalation.

**6. Proposed Test:**

1. Obtain a valid session cookie.
2. Decode the cookie.
3. Modify the payload to set the following attributes:

```json
{
    "role": "admin",
    "user": "admin1"
}
```

4. Re-sign the cookie using the HMAC secret `dev-secret-key`.
5. Send the forged cookie in a request to `/me`.

If the server accepts the forged session, the vulnerability claim is confirmed.

**7. Assumptions & Confidence:**

Assumes Flask client-side sessions are in use and that the application trusts the relevant session attributes for authorization decisions.

**Confidence:** High.

---

### SEC-05: Verbose Error Handling and Debug Mode Enabled

**1. Identifier and Title:**  
SEC-05 - Verbose Error Handling