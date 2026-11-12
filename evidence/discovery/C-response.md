# Static Security Review – Application Source Code

**Target File:** `baseline_secure_coding_api.py`  
**Evaluation Scope:** Application Context and Security Requirements (R1–R7)

---

## 1. Findings Summary Table

| ID | Title | Affected File, Function, & Lines | Violated Requirement | Impact |
|---|---|---|---|---|
| **VULN-01** | Missing Authentication on Protected Endpoints | `baseline_secure_coding_api.py`, `get_profile`, `get_grades`, `update_grade`, `download_file` (Lines 122–154) | R1 | Unauthenticated users can access sensitive profile, grade, file download, and grade update endpoints. |
| **VULN-02** | Broken Object Level Authorization (BOLA) & Role Scope Violations | `baseline_secure_coding_api.py`, `get_profile`, `get_grades`, `update_grade` (Lines 122–147) | R2, R3, R4 | Users can view or modify records belonging to other students or courses they are not assigned to. |
| **VULN-03** | Path Traversal / Arbitrary File Read | `baseline_secure_coding_api.py`, `download_file` (Lines 150–154) | R6 | Attackers can download arbitrary files from the host filesystem outside the `materials` directory. |
| **VULN-04** | Missing Input Validation & Type Enforcement on Grade Updates | `baseline_secure_coding_api.py`, `update_grade` (Lines 133–147) | R5 | Acceptance of malformed payloads, out-of-range grades, boolean values, and unknown courses. |
| **VULN-05** | Information Disclosure via Global Exception Handler | `baseline_secure_coding_api.py`, `handle_error` (Lines 156–161) | R7 | Exposes internal exception class names and raw error strings to clients on failure. |

---

## 2. Detailed Findings and Supporting Explanations

### VULN-01: Missing Authentication on Protected Endpoints

**1. Finding Identifier & Title:**

`VULN-01` — Missing Authentication on Protected Endpoints.

**2. Affected File, Function, & Location:**

`baseline_secure_coding_api.py`, functions:

- `get_profile()` (lines 122–128).
- `get_grades()` (lines 130–132).
- `update_grade()` (lines 133–147).
- `download_file()` (lines 150–154).

**3. Attacker-Controlled Input & Execution Path:**

HTTP requests are made directly to the following endpoints without establishing a session via `/login`:

```http
/students/<student_id>/profile
/grades/<student_id>
/grades/update
/files?path=...
```

The execution flows directly into the endpoint handlers without inspecting:

```python
flask.session.get("user")
```

**4. Missing Security Control & Root Cause:**

The application lacks session validation decorators or conditional checks verifying that `flask.session` contains an authenticated user before processing requests.

The root cause is the omission of authentication guards on protected routes.

**5. Preconditions & Potential Impact:**

- **Preconditions:** The application must be running.
- **Impact:** Complete bypass of authentication requirements (R1), allowing anonymous users to retrieve profiles, grades, files, and modify academic records.

**6. Proposed Test:**

Send an unauthenticated HTTP GET request to:

```http
GET /students/1001/profile
```

Alternatively:

```http
GET /files?path=srs-summary.txt
```

Confirm that the application returns resource data with a `200 OK` status instead of a `401 Unauthorized` response.

**7. Assumptions, Uncertainty, & Confidence:**

- **Confidence:** High.
- **Evidence:** Code inspection confirms zero session checks on these four route handlers.

---

### VULN-02: Broken Object Level Authorization (BOLA) & Role Scope Violations

**1. Finding Identifier & Title:**

`VULN-02` — Broken Object Level Authorization (BOLA) & Role Scope Violations.

**2. Affected File, Function, & Location:**

`baseline_secure_coding_api.py`, functions:

- `get_profile()` (lines 122–128).
- `get_grades()` (lines 130–132).
- `update_grade()` (lines 133–147).

**3. Attacker-Controlled Input & Execution Path:**

The attacker supplies the `student_id` path parameter and request payload values.

The functions use `int(student_id)` or raw payload fields directly against `STUDENT_PROFILES` and `GRADES` without cross-referencing the caller's:

- Identity.
- Role (`student`, `professor`, `admin`).
- Associated `student_id`.
- Assigned `courses` from `flask.session`.

**4. Missing Security Control & Root Cause:**

Complete authorization checks (R4) and role-scoping controls (R2, R3) are absent.

The root cause is trusting client input parameters without validating ownership or role permissions.

**5. Preconditions & Potential Impact:**

- **Preconditions:** Access to the API, authenticated or unauthenticated.
- **Impact:**
  - Student privacy breaches, allowing students to read other students' profiles and grades.
  - Professor scope violations, allowing professors to read or update courses they do not teach or access student profiles outside their permissions.
  - Unauthorized grade updates.

**6. Proposed Test:**

Authenticate as student `alice` (`student_id: 1001`).

Then send a GET request to:

```http
GET /students/1002/profile
```

Or:

```http
GET /grades/1002
```

Confirm whether Bob's private data is returned instead of a `403 Forbidden` error.

**7. Assumptions, Uncertainty, & Confidence:**

- **Confidence:** High.
- **Evidence:** No permission checks comparing session attributes against requested resources exist in the source code.

---

### VULN-03: Path Traversal / Arbitrary File Read

**1. Finding Identifier & Title:**

`VULN-03` — Path Traversal / Arbitrary File Read.

**2. Affected File, Function, & Location:**

`baseline_secure_coding_api.py`, function `download_file()` (lines 150–154).

**3. Attacker-Controlled Input & Execution Path:**

The attacker controls the query parameter `path`:

```python
raw_path = flask.request.args.get("path", "")
```

The input is concatenated directly to `MATERIALS_DIR` via:

```python
target = MATERIALS_DIR / raw_path
```

The resulting path is then passed to:

```python
flask.send_file(target)
```

**4. Missing Security Control & Root Cause:**

The application lacks:

- Path sanitization.
- Boundary checking.
- Resolution validation.

For example, the application should ensure that:

```python
target.resolve().is_relative_to(MATERIALS_DIR.resolve())
```

The root cause is the insecure combination of user input with filesystem paths.

**5. Preconditions & Potential Impact:**

- **Preconditions:** Access to the `/files` endpoint.
- **Impact:** Arbitrary file read vulnerability (R6), allowing attackers to traverse outside the materials directory and read sensitive system files (e.g., `/etc/passwd` or application source code).

**6. Proposed Test:**

Send a GET request to:

```http
GET /files?path=../../etc/passwd
```

Alternatively, use a known file outside the intended directory.

Confirm whether the file content is returned.

**7. Assumptions, Uncertainty, & Confidence:**

- **Confidence:** High.
- **Evidence:** Path arithmetic via `pathlib.Path /` does not prevent parent directory traversal (`..`) when `raw_path` contains relative path sequences.

---

### VULN-04: Missing Input Validation & Type Enforcement on Grade Updates

**1. Finding Identifier & Title:**

`VULN-04` — Missing Input Validation & Type Enforcement on Grade Updates.

**2. Affected File, Function, & Location:**

`baseline_secure_coding_api.py`, function `update_grade()` (lines 133–147).

**3. Attacker-Controlled Input & Execution Path:**

The JSON body payload is retrieved using:

```python
flask.request.get_json()
```

The following fields are accessed and written directly to memory (`GRADES`) without validation:

- `student_id`
- `course_id`
- `grade`

**4. Missing Security Control & Root Cause:**

Strict input validation (R5) is missing.

The root cause is the assumption that input payloads are well-formed and valid, without verifying that:

- `student_id` is a positive integer.
- `course_id` belongs to `["SRS", "SSD"]`.
- `grade` is numeric and between `0` and `20` inclusive.
- `grade` is not a boolean, since Python booleans inherit from integers.
- All required fields are present in the request.

**5. Preconditions & Potential Impact:**

- **Preconditions:** Sending a POST request to `/grades/update`.
- **Impact:** Data corruption, injection of invalid course identifiers, out-of-range grades, boolean values, or unhandled exceptions caused by missing keys.

**6. Proposed Test:**

Send a POST request to `/grades/update` with the following JSON payload:

```json
{
    "student_id": -1,
    "course_id": "INVALID",
    "grade": true
}
```

Confirm that the application updates or corrupts the database state instead of rejecting the input with a client error.

**7. Assumptions, Uncertainty, & Confidence:**

- **Confidence:** High.
- **Evidence:** Code inspection reveals direct dictionary access on `data` and no range or type checks on `student_id`, `course_id`, or `grade`.

---

### VULN-05: Information Disclosure via Global Exception Handler

**1. Finding Identifier & Title:**

`VULN-05` — Information Disclosure via Global Exception Handler.

**2. Affected File, Function, & Location:**

`baseline_secure_coding_api.py`, function `handle_error()`, decorated with:

```python
@app.errorhandler(Exception)
```

Lines 156–161.

**3. Attacker-Controlled Input & Execution Path:**

Any malformed request or trigger causing an unhandled exception flows into `handle_error(exc)`.

Examples include:

- Missing JSON keys in `update_grade()`.
- Invalid type casting in `get_profile()`.

**4. Missing Security Control & Root Cause:**

Proper error handling (R7) requires that invalid requests return appropriate client errors without exposing internal paths, tracebacks, or implementation exception details.

The root cause is returning:

```python
str(exc)
exc.__class__.__name__
```

in a JSON response with a `500 Internal Server Error` status.

**5. Preconditions & Potential Impact:**

- **Preconditions:** The attacker must be able to trigger an application exception.
- **Impact:** Information disclosure (R7), exposing internal implementation details, exception types, and potential application logic clues to attackers.

**6. Proposed Test:**

Send a POST request to `/grades/update` with an empty JSON body:

```json
{}
```

Inspect the JSON response to verify whether internal exception names (e.g., `KeyError`) and error details are disclosed.

**7. Assumptions, Uncertainty, & Confidence:**

- **Confidence:** High.
- **Evidence:** The exception handler explicitly formats and returns `exc.__class__.__name__` and `str(exc)`.

---

## 3. Overall Security Assessment

The static security review identified five vulnerabilities in `baseline_secure_coding_api.py`, evaluated against the application's security requirements (R1–R7).

The findings affect several fundamental security properties:

- **Authentication (R1):** VULN-01 allows unauthenticated users to access protected application endpoints.
- **Role-Based Access Control (R2, R3):** VULN-02 allows users to perform actions outside their assigned roles and permissions.
- **Authorization (R4):** VULN-02 enables unauthorized access to student records and academic resources.
- **Input Validation (R5):** VULN-04 allows malformed and invalid data to be processed and stored.
- **Filesystem Security (R6):** VULN-03 exposes files outside the intended materials directory.
- **Error Handling (R7):** VULN-05 discloses internal application details through verbose exception responses.

### 3.1. Recommended Remediation Priorities

The following remediation measures are recommended:

1. **VULN-01 – Authentication:** Implement session-based authentication checks on all protected endpoints.
2. **VULN-02 – Authorization:** Enforce role-based access control and object-level permission checks for students, professors, and administrators.
3. **VULN-03 – Path Traversal:** Normalize and validate filesystem paths, ensuring that resolved files remain within the intended materials directory.
4. **VULN-04 – Input Validation:** Validate all incoming JSON fields, enforce strict data types, check allowed course identifiers, and restrict grades to the range of 0–20.
5. **VULN-05 – Error Handling:** Return generic error messages to clients, log detailed exceptions internally, and avoid exposing implementation details.

### 3.2. Conclusion

The identified vulnerabilities demonstrate that the application does not fully satisfy its security requirements (R1–R7).

The most critical issues concern missing authentication, inadequate authorization controls, and unrestricted filesystem access.

These vulnerabilities should be addressed before deploying the application in a production environment.

A comprehensive security validation should also be performed after remediation to verify that all requirements are correctly enforced.