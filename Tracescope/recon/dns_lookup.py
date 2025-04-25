import dns.resolver

def resolve(domain, record_type):
    try:
        return [str(r) for r in dns.resolver.resolve(domain, record_type)]
    except:
        return []

def lookup_all(domain):
    return {
        "A": resolve(domain, "A"),
        "MX": resolve(domain, "MX"),
        "NS": resolve(domain, "NS")
    }
