# HeaderShock
<p align="center">
  <img src="HeaderShock.jpg" width="100%" alt="GitBlast Banner">
</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**HeaderShock** is a powerful HTTP header fuzzer that detects anomalies, misconfigurations, and leaks using raw socket precision. This tool acts as your lens into the behavior of web servers under crafted, strange, and non-standard HTTP headers.

---

## Features

- Sends malformed, duplicated, or non-standard HTTP headers
- Uses raw sockets to bypass limitations of standard HTTP libraries
- Detects response anomalies, new headers, info leaks, and status changes
- Compares all responses to a baseline request for accurate diffing
- Supports three fuzzing depths: `light`, `medium`, and `deep`
- Beautiful terminal output with color-coded insights
- Saves markdown reports with all results and findings

---

## Usage

Basic usage:

```bash
headershock -url https://target.com
```

Set depth level and enable raw socket mode:

```bash
headershock -url https://target.com -depth deep -raw
```

Verbose mode with multithreading:

```bash
headershock -url https://target.com -depth medium -threads 10 -verbose
```

Save results to file:

```bash
headershock -url https://target.com -save -output results.md
```

---

## Command-Line Arguments

| Argument            | Description |
|---------------------|-------------|
| `-url`              | Target URL (required) |
| `-depth`            | Testing depth: `light`, `medium`, `deep` (default: `medium`) |
| `-delay`            | Base delay between requests in seconds (default: `0.5`) |
| `-raw`              | Use raw sockets for all requests |
| `-verbose`          | Enable verbose output |
| `-threads`          | Number of concurrent threads (default: `1`) |
| `-timeout`          | Timeout for each request in seconds (default: `10`) |
| `-save`             | Save results to a markdown file |
| `-output`           | Output file name (default: `fuzzer-results.md`) |
| `-user-agent`       | Custom User-Agent string (default: `GoHTTPFuzzer/1.0`) |

---

## Fuzzing Depths

- **Light**: Basic method tampering and malformed headers.
- **Medium**: Adds duplicated headers, smuggling attempts, random cookies, and more.
- **Deep**: Full suite of advanced fuzzing including malformed chunked encodings, HTTP/2 edge cases, and unusual cache headers.

---

## What It Finds

- **Interesting status codes** (e.g., 405, 500)
- **Unexpected or new headers** compared to baseline
- **Reflected or leaked info in body** (e.g., stack traces, file paths, IPs, credentials)
- **Header smuggling conditions**
- **Server misconfigurations or inconsistencies**

---

## Output Example

```
Test: Multiple Host headers
Status: 400
Response time: 120ms
New headers appeared: X-Debug-ID
Potential info leaks in body:
  - Stack trace found: NullPointerException
  - File path found: /var/www/html/index.php
```
<img width="722" alt="headershock-output" src="https://github.com/user-attachments/assets/4e61cad0-3b06-4db0-9406-6329198e3d01" />

---

## Saving Results

Use `-save` to export all test results to a markdown file, including baseline comparisons, headers, anomalies, and info leaks.

Example:
```bash
headershock -url https://example.com -save -output shock-results.md
```

---

## License

HeaderShock is released under the [MIT License](https://opensource.org/licenses/MIT).

---

## Author

**Vahe Demirkhanyan**  

[https://www.linkedin.com/in/vahearamian/](https://www.linkedin.com/in/vahearamian/)

[https://hackvector.io](https://hackvector.io)

---

HeaderShock: Investigate your headers. Find the truth.

