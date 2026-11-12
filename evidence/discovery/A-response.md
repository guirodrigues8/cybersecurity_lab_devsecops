# Static Security Findings

## 1. Findings Table

| ID | Title | Severity | Affected Location | Primary Vulnerability Type |
|---|---|---|---|---|
| **VULN-01** | Path Traversal / Arbitrary File Read | High | `baseline_secure_coding_api.py`, `download_file()`, lines 133–137 | Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) |
| **VULN-02** | Missing Authentication & Authorization on Grade Updates | High | `baseline_secure_coding_api.py`, `update_grade()`, lines 120–131 | Missing Authentication / Broken Access Control |
| **VULN-03** | Broken Object Level Authorization (BOLA) on Student Data | Medium-High | `baseline_secure_coding_api.py`, `get_profile()` & `get_grades()`, lines 108–118 | Broken Object Level Authorization |
| **VULN-04** | Hardcoded Flask Session Secret Key | Medium | `baseline_secure_coding_api.py`, module level, line 7 | Hardcoded Cryptographic Key |
| **VULN-05** | Verbose Error Handling and Debug Mode Enabled | Low-Medium | `baseline_secure_coding_api.py`, `handle_error()` & `app.run()`, lines 139–149 | Information Disclosure |

---

## 2. Supporting Explanations

### VULN-01: Path Traversal / Arbitrary File Read

**1. Finding Identifier & Title:**

VULN-01 - Path Traversal in File Download Endpoint.

**2. Affected File, Function, and Line:**

`baseline_secure_coding_api.py`, function `download_file()`, lines 133–137.

**3. Attacker-Controlled Input & Data-Flow Path:**

The attacker supplies the `path` query parameter via HTTP GET:

```python
flask.request.args.get("path", "")
```

This raw string is concatenated directly to `MATERIALS_DIR` using:

```python
target = MATERIALS_DIR / raw_path
```

The resulting path is passed directly into:

```python
flask.send_file(target)
```

No sanitization or boundary checks are performed.

**4. Missing Security Control & Root Cause:**

The root cause is the lack of path normalization and validation.

The application fails to verify that the resolved target path remains within the intended `MATERIALS_DIR` directory (e.g., via `pathlib.Path.resolve()` and relative path checks).

**5. Preconditions & Impact:**

- **Preconditions:** The application must be running and reachable; the user process must have read permissions on target files.
- **Impact:** An attacker can traverse the file system using sequences like `path=../../etc/passwd` to read arbitrary system files accessible to the Flask application process.

**6. Proposed Test:**

Send an HTTP GET request to:

```http
GET /files?path=../../etc/passwd
```

Alternatively, use an equivalent accessible file on the host operating system.

Confirm rejection if proper sanitization is implemented, or observe successful file content retrieval if the application is vulnerable.

**7. Assumptions, Uncertainty, & Confidence:**

- **Demonstrated Fact:** `target = MATERIALS_DIR / raw_path` directly combines user input with a `pathlib.Path` object without boundary validation.
- **Confidence:** High.

---

### VULN-02: Missing Authentication & Authorization on Grade Updates

**1. Finding Identifier & Title:**

VULN-02 - Unauthorized Grade Modification/Creation.

**2. Affected File, Function, and Line:**

`baseline_secure_coding_api.py`, function `update_grade()`, lines 120–131.

**3. Attacker-Controlled Input & Data-Flow Path:**

The attacker sends an HTTP POST request to `/grades/update` with an arbitrary JSON body containing:

- `student_id`
- `course_id`
- `grade`

The data is retrieved using:

```python
data = flask.request.get_json()
```

It is then processed and written directly to the in-memory `GRADES` list or dictionary structure without verifying session state.

**4. Missing Security Control & Root Cause:**

The endpoint lacks authentication and role-based access control (RBAC).

The root cause is the total absence of checks against `flask.session` to ensure that the caller is authenticated and holds a privileged role (such as `"professor"` or `"admin"`).

**5. Preconditions & Impact:**

- **Preconditions:** Network access to `/grades/update`.
- **Impact:** Any unauthenticated or unauthorized user can arbitrarily alter, forge, or insert student grades.

**6. Proposed Test:**

Send a POST request containing the following JSON payload without a login cookie or session:

```json
{
    "student_id": 1001,
    "course_id": "SRS",
    "grade": 20
}
```

Check whether a subsequent GET request to `/grades/1001` reflects the modified grade.

**7. Assumptions, Uncertainty, & Confidence:**

- **Demonstrated Fact:** `update_grade()` reads JSON input and mutates `GRADES` without inspecting `flask.session`.
- **Confidence:** High.

---

### VULN-03: Broken Object Level Authorization (BOLA) on Student Data

**1. Finding Identifier & Title:**

VULN-03 - Broken Object Level Authorization on Profiles and Grades.

**2. Affected File, Function, and Line:**

`baseline_secure_coding_api.py`, functions:

- `get_profile()`
- `get_grades()`

Lines 108–118.

**3. Attacker-Controlled Input & Data-Flow Path:**

The attacker supplies the `student_id` path parameter through the following endpoints:

```http
/students/<student_id>/profile
/grades/<student_id>
```

The application looks up data using `int(student_id)` directly from dictionaries and lists without verifying whether the logged-in session user is authorized to access that specific student's record.

**4. Missing Security Control & Root Cause:**

Missing authorization checks.

The root cause is that the endpoints assume that knowing or guessing a numeric ID grants legitimate access rights.

**5. Preconditions & Impact:**

- **Preconditions:** Knowledge or enumeration of valid student IDs (e.g., `1001`, `1002`).
- **Impact:** Horizontal privilege escalation and information disclosure, allowing users or unauthenticated attackers to harvest student profiles (names, emails, programs) and grades.

**6. Proposed Test:**

Access the following endpoints as an unauthenticated user or as student `1002`:

```http
GET /students/1001/profile
GET /grades/1001
```

Verify whether student `1001`'s private data is returned.

**7. Assumptions, Uncertainty, & Confidence:**

- **Demonstrated Fact:** `get_profile()` and `get_grades()` accept arbitrary `student_id` path variables and return data without validating session ownership or role.
- **Confidence:** High.

---

### VULN-04: Hardcoded Flask Session Secret Key

**1. Finding Identifier & Title:**

VULN-04 - Hardcoded Application Secret Key.

**2. Affected File, Function, and Line:**

`baseline_secure_coding_api.py`, line 7:

```python
app.config["SECRET_KEY"] = "dev-secret-key"
```

**3. Attacker-Controlled Input & Data-Flow Path:**

No direct attacker-controlled input is required.

However, the predictable secret key is utilized by Flask's session management infrastructure to cryptographically sign cookies.

**4. Missing Security Control & Root Cause:**

Use of a static, hardcoded secret key (`"dev-secret-key"`) in production-ready code instead of loading a high-entropy secret from environment variables.

**5. Preconditions & Impact:**

- **Preconditions:** The application uses Flask sessions (e.g., `flask.session["user"]`).
- **Impact:** Because the secret key is public and predictable, an attacker can forge signed session cookies, potentially allowing full privilege escalation (e.g., crafting a session cookie claiming `role: "admin"` or `user: "admin1"`).

**6. Proposed Test:**

Inspect the source code or attempt cookie forgery using the known `"dev-secret-key"` string with a tool such as `itsdangerous` to sign a custom payload.

**7. Assumptions, Uncertainty, & Confidence:**

- **Demonstrated Fact:** `app.config["SECRET_KEY"] = "dev-secret-key"` is explicitly defined in the source code.
- **Confidence:** High.

---

### VULN-05: Verbose Error Handling and Debug Mode Enabled

**1. Finding Identifier & Title:**

VULN-05 - Information Disclosure via Exception Handling and Debug Mode.

**2. Affected File, Function, and Line:**

`baseline_secure_coding_api.py`, functions:

- `handle_error()`
- `app.run()`

Lines 139–149.

**3. Attacker-Controlled Input & Data-Flow Path:**

Any malformed request or trigger causing an unhandled exception flows into `handle_error(exc)`.

The handler serializes the following information into the JSON response:

```python
str(exc)
exc.__class__.__name__
```

Additionally, the application runs with:

```python
app.run(debug=True, ...)
```

**4. Missing Security Control & Root Cause:**

The root cause is the exposure of internal exception details to clients through:

- Returning raw exception strings.
- Returning exception class names.
- Running Flask in debug mode.

**5. Preconditions & Impact:**

- **Preconditions:** The application encounters runtime errors or exceptions.
- **Impact:** Exposes internal application details, database or data structure information, and file path structures to potential attackers.

**6. Proposed Test:**

Trigger an intentional exception, for example by sending invalid JSON types to `/grades/update`.

Inspect the JSON error response for verbose exception details.

**7. Assumptions, Uncertainty, & Confidence:**

- **Demonstrated Fact:** `handle_error()` returns `str(exc)` and `exc.__class__.__name__`, and `debug=True` is set in `app.run()`.
- **Confidence:** High.

---

## 3. Overall Security Assessment

The static security analysis identified five vulnerabilities in `baseline_secure_coding_api.py`, with severity levels ranging from Low-Medium to High.

The findings affect several fundamental security properties:

- **Confidentiality:** VULN-01 and VULN-03 expose sensitive filesystem and student information.
- **Integrity:** VULN-02 allows unauthorized modification and creation of academic records.
- **Authentication and Authorization:** VULN-02 and VULN-03 undermine access control mechanisms, while VULN-04 may enable session forgery and privilege escalation.
- **Information Disclosure:** VULN-05 exposes internal application details through verbose error handling and debug mode.

### Recommended Priorities

The following remediation priorities are recommended:

1. **High Priority:** Implement secure filesystem path validation to prevent directory traversal.
2. **High Priority:** Enforce authentication and role-based authorization on grade modification endpoints.
3. **Medium-High Priority:** Implement object-level authorization checks to restrict access to student profiles and grades.
4. **Medium Priority:** Replace the hardcoded Flask secret key with a cryptographically secure secret loaded from environment variables.
5. **Low-Medium Priority:** Disable debug mode in production and return generic error messages to clients.

These vulnerabilities should be addressed before deploying the application in a production environment.