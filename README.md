# SSRF-Fuzzing-
A Python SSRF fuzzing tool that automatically tests unique SSRF payloads against a target endpoint.
The fuzzer appends each payload using the format /?url=(payload) and sends the request to observe how the server responds.
Every result is returned in a structured dictionary containing the payload used, the full test URL, the status code, response length, and any notes for abnormal behavior.

This tool is ideal for:

>> understanding SSRF behavior in real-world applications

>> comparing server responses across multiple payload types

>> quickly identifying interesting patterns, filters, or misconfigurations

>> learning web exploitation in a safe environment.

🧩 **How It Works**

For each payload in the wordlist, the fuzzer builds a test URL, sends the request, and appends the result to a list:

results.append({
    "payload": payload,
    "url": test_url,
    "status": status,
    "length": length,
    "note": note
})


**Where:**

payload → the SSRF string being tested

test_url → the full URL, e.g. https://target.com/?url=(payload)

status → HTTP status code returned by the server

length → length of the response body

note → any extra info/flags you add (e.g. “redirect”, “timeout”, “suspicious length”, etc.)

📦 **Installation**

# 1. Clone the repository
git clone https://github.com/clashroyale2025111-stack/SSRF-Fuzzing-.git/
cd SSRF-Fuzzing-

# 2. Install dependencies
pip install -r requirements.txt

🚀 **Usage**

python ssrf_fuzzer.py



