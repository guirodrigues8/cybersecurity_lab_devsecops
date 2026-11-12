# 14. Comparison of the Outcomes

This section compares the vulnerabilities identified during the three LLM analysis conditions (A, B and C), the findings reported by Bandit and Semgrep, the proposed repairs, and the results of the regression tests.

## 14.1 Consolidated findings table

| ID | Finding | LLM A | LLM B | LLM C | Bandit | Semgrep | Validation |
|---|---|:---:|:---:|:---:|:---:|:---:|---|
| F1 | Path traversal / arbitrary file read | ✓ | ✓ | Addressed in proposed patch | — | — | Confirmed before patch; 2 regression tests passed after patch |
| F2 | Missing authorisation on grade updates | ✓ | ✓ | Addressed in proposed patch | — | — | Identified by LLMs; not selected for regression validation |
| F3 | BOLA in student profiles and grades | ✓ | ✓ | Addressed in proposed patch | — | — | Confirmed before patch; regression tests passed after patch |
| F4 | Hardcoded Flask secret key | ✓ | ✓ | Not fixed in proposed implementation | ✓ | — | Scanner finding; not independently validated |
| F5 | Hardcoded plaintext user passwords | — | ✓ | Not fixed in proposed implementation | ✓ | — | Scanner finding; not independently validated |
| F6 | Verbose error disclosure | ✓ | ✓ | Addressed in proposed patch | — | — | Identified by LLMs; not selected for regression validation |
| F7 | Flask debug mode enabled | ✓ | — | Not fixed in proposed implementation | ✓ | ✓ | Confirmed by static analysis |
| F8 | Application bound to all network interfaces (`0.0.0.0`) | — | — | Not fixed in proposed implementation | ✓ | ✓ | Confirmed by static analysis |
| F9 | Insufficient input validation on grade updates | — | ✓ | Addressed in proposed patch | — | — | Identified by LLM B; not independently validated |

**Legend:** ✓ = identified; — = not identified. "Addressed in proposed patch" means that the LLM proposed a change intended to address the issue; it does not mean that the change was independently verified.

Repeated descriptions of the same missing authorisation check should not be counted as separate vulnerabilities. F3 represents the BOLA issue selected for testing, while F2 concerns the separate grade-update operation.

## 14.2 Vulnerability discovery

### Condition A – Source code only

With access only to the source code, LLM A identified several security weaknesses, including path traversal, missing authorisation checks, BOLA vulnerabilities, hardcoded secrets and verbose error disclosure. It also identified the use of Flask debug mode.

This demonstrates that source-code analysis alone can identify important vulnerabilities, although it does not provide all the information needed to understand the application's intended access-control rules.

### Condition B – Source code and application context

Providing additional application context helped LLM B identify further issues, particularly hardcoded plaintext user passwords and insufficient input validation in grade updates.

LLM B also identified the vulnerabilities already detected in Condition A, including path traversal and BOLA. This suggests that contextual information helped broaden the analysis and identify weaknesses that were not explicitly reported in Condition A.

### Condition C – Source code, context and security requirements

Condition C focused on proposing a more secure implementation. Its proposed changes addressed several previously identified issues, including path traversal, BOLA, missing authorisation and input validation.

However, the proposed implementation did not eliminate every security concern. It retained the hardcoded Flask secret, plaintext passwords, debug mode and binding to `0.0.0.0`. Therefore, even when security requirements were provided, the generated implementation was not fully secure and required further review.

### Comparison with Bandit and Semgrep

The static analysis tools produced fewer findings but identified several concrete configuration and coding issues:

- Bandit 1.9.4 reported seven findings: one High, one Medium and five Low severity findings. These included Flask debug mode, binding to all network interfaces, a hardcoded secret key and hardcoded passwords.
- Semgrep 1.183.0 reported two warnings: Flask debug mode and binding to all network interfaces.

Neither Bandit nor Semgrep identified the BOLA or path traversal vulnerabilities found by the LLMs. These results demonstrate the complementary nature of the approaches: LLMs identified application-level security weaknesses, while static analysis tools detected specific insecure configurations and coding patterns.

### Findings missed, incorrect findings and unresolved claims

The main weaknesses missed by the static analysis tools were BOLA, path traversal, missing authorisation on grade updates and insufficient input validation.

Conversely, the LLM-generated implementation failed to address some of the issues detected by static analysis, particularly the hardcoded secret, plaintext passwords, debug mode and binding to all network interfaces.

Based on the available results, no specific LLM finding has been conclusively demonstrated to be a false positive. However, findings that were not independently tested must be treated as identified or suspected issues rather than confirmed vulnerabilities. In particular, F2, F4, F5, F6, F7, F8 and F9 were not independently validated through dedicated regression tests.

## 14.3 Vulnerability repair

Two vulnerabilities were selected for repair and regression testing: BOLA and path traversal.

### BOLA repair

The initial LLM-generated proposal introduced authentication checks and role-based authorisation. However, further review identified implementation details that required attention, particularly the comparison between the student ID stored in the session and the requested student ID.

The improved proposal introduced separate access rules for students, professors and administrators. It used the server-side course associations to restrict professors' access to students within their authorised courses.

The implementation was reviewed against the application's existing data structures and role definitions before being applied.

### Path traversal repair

The path traversal repair introduced path resolution and a containment check to ensure that requested files remained inside the permitted materials directory. It also rejected invalid paths and non-file targets.

This prevented access through both relative traversal paths and absolute paths while preserving access to permitted files.

### Manual corrections and functional impact

After applying the security changes, the original API tests initially exposed two failures. Both tests attempted to access protected endpoints without authenticating, resulting in HTTP 401 responses instead of the expected HTTP 200 responses.

This was not a reason to remove the new authentication checks. Instead, the original tests were updated to authenticate before accessing the protected resources.

The final test results confirmed that the updated application preserved the tested legitimate functionality while enforcing the new access restrictions.

Overall, the LLM-generated patches provided a useful starting point, but human review and corrections were necessary before the implementation could be considered validated.

## 14.4 Verification

The repairs were evaluated by comparing the regression test results before and after applying the patches.

| Test suite | Before patch | After patch |
|---|---:|---:|
| Security regression tests | 3 passed, 4 failed | 7 passed |
| Original API tests | Not recorded in the initial pre-patch evidence | 5 passed |

Before the repair, four security regression tests failed:

- Two BOLA tests demonstrated that a student could access another student's profile and grades.
- Two path traversal tests demonstrated that files outside the permitted directory could be accessed.

In the path traversal tests, the response body contained `CONFIDENTIAL OUTSIDE FILE`, confirming that the issue allowed disclosure of file contents rather than merely returning an unexpected HTTP status.

After applying the fixes, all seven security regression tests passed. This included the tests for legitimate access to the student's own information and permitted file downloads, as well as the tests preventing unauthorised access.

The original API test suite initially had two failures because the tests did not authenticate before accessing protected endpoints. After updating those tests to follow the application's authentication requirements, all five original tests passed.

These results provide evidence that the selected vulnerabilities were successfully addressed without breaking the functionality covered by the test suites.

The CI workflow was also configured so that the Docker build job depends on the original tests, static analysis and security regression tests. Consequently, a failure in any required job prevents the build job from proceeding.

**Note:** The local test results are confirmed by the terminal output. The GitHub Actions outcome should only be reported as successful after checking the corresponding workflow execution in the repository.

## 14.5 Overall conclusion

The experiment demonstrates that LLM-assisted vulnerability discovery and repair can complement traditional static analysis tools. The LLMs identified application-level vulnerabilities that Bandit and Semgrep did not detect, particularly BOLA and path traversal. Additional application context helped identify further weaknesses, while explicit security requirements guided the generation of proposed repairs.

However, the generated implementation was not completely secure and required human review and corrections. The final regression tests demonstrated that the two selected vulnerabilities were addressed, while the original API tests confirmed that the tested functionality remained operational.

The results support using LLMs as an assistance mechanism rather than as a replacement for static analysis, manual security review and automated testing. 