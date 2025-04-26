import dns.resolver

def dns_enum(domain, brute_file=None):
    """
    Perform DNS enumeration on the given domain.
    - domain: Target domain to query (str).
    - brute_file: Optional path to a wordlist file for subdomain brute-forcing.
    Returns a dictionary with:
      A: [list of IPs],
      MX: [list of mail servers],
      NS: [list of name servers],
      subdomains: [dicts of found subdomain -> IPs].
    """
    print(f"[+] Performing DNS lookup for {domain}")
    results = {"domain": domain, "A": [], "MX": [], "NS": [], "subdomains": []}
    try:
        # Query A records
        try:
            answers = dns.resolver.resolve(domain, 'A', raise_on_no_answer=False)
            for r in answers:
                results["A"].append(r.to_text())
        except Exception as e:
            print(f"[-] A record lookup failed: {e}")
        # Query MX records
        try:
            answers = dns.resolver.resolve(domain, 'MX', raise_on_no_answer=False)
            for r in answers:
                # Format: "mailserver (priority X)"
                results["MX"].append(f"{r.exchange.to_text().rstrip('.')} (priority {r.preference})")
        except Exception as e:
            print(f"[-] MX record lookup failed: {e}")
        # Query NS records
        try:
            answers = dns.resolver.resolve(domain, 'NS', raise_on_no_answer=False)
            for r in answers:
                results["NS"].append(r.to_text())
        except Exception as e:
            print(f"[-] NS record lookup failed: {e}")
        # Optional subdomain brute-forcing
        if brute_file:
            print(f"[+] Performing subdomain brute-forcing using wordlist {brute_file}")
            try:
                with open(brute_file, 'r') as f:
                    subs = [line.strip() for line in f if line.strip()]
                for sub in subs:
                    full_sub = f"{sub}.{domain}"
                    try:
                        answers = dns.resolver.resolve(full_sub, 'A', raise_on_no_answer=False)
                        ips = [r.to_text() for r in answers]
                        if ips:
                            results["subdomains"].append({"subdomain": full_sub, "A": ips})
                            print(f"[+] Found subdomain: {full_sub} -> {ips}")
                    except Exception:
                        # Ignore unresolved subdomains
                        continue
            except FileNotFoundError:
                print(f"[-] Wordlist file not found: {brute_file}")
            except Exception as e:
                print(f"[-] Error during subdomain brute-forcing: {e}")
    except Exception as e:
        print(f"[-] DNS enumeration error: {e}")
        return {"error": str(e)}
    return results
