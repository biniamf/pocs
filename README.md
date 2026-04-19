# pocs

Proof-of-concept files for vulnerabilities discovered in open-source libraries using a
research prototype for automated vulnerability discovery.

Each subdirectory targets a specific bug and contains:
- A minimal crafted input file to trigger the vulnerability
- Build instructions for the affected library (with sanitizer flags)
- The exact command to reproduce the crash and expected output

## Usage

Every PoC follows the same general pattern:

1. Build the target library/harness with AddressSanitizer and/or UBSan as described
   in the subdirectory README.
2. Run the provided command against the PoC input file.
3. Observe the sanitizer report.


## Disclaimer

These files are provided for security research and responsible disclosure purposes only. The PoC inputs are crafted solely to trigger the described bugs in instrumented (sanitizer) builds for verification. Do not use against systems without explicit authorization.

---

## Disclosure

All vulnerabilities were reported to the respective maintainers prior to
publication. PoC files are shared for verification and research purposes only.




