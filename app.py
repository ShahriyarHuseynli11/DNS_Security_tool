from flask import Flask, request, render_template
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.dnssec
import dns.name
import dns.exception

app = Flask(__name__)
cache = {}

# DNS Cache ilə sorğu
def resolve_with_cache(domain, record_type='A'):
    key = (domain, record_type)
    if key in cache:
        return cache[key]

    try:
        answers = dns.resolver.resolve(domain, record_type)
        result = [rdata.to_text() for rdata in answers]
        cache[key] = result
        return result
    except Exception as e:
        return [f"Xəta: {e}"]

# DNSSEC cavabları (DNSKEY)
def resolve_dnssec(domain):
    try:
        request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(request, '8.8.8.8')
        results = [ans.to_text() for ans in response.answer]
        if not results:
            results.append("DNSSEC cavabı yoxdur və ya domen DNSSEC dəstəkləmir.")
        return results
    except Exception as e:
        return [f"DNSSEC xətası: {e}"]


def verify_dnssec(domain):
    try:
        name = dns.name.from_text(domain)
        request = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(request, '8.8.8.8')
        dnskey_rrset = None
        rrsig = None

        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                dnskey_rrset = rrset
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig = rrset

        if dnskey_rrset and rrsig:
            dns.dnssec.validate(dnskey_rrset, rrsig, {name: dnskey_rrset})
            return ["✅ DNSSEC imzası etibarlıdır."]
        return ["⚠️ DNSSEC imzası yoxlanmadı."]
    except dns.dnssec.ValidationFailure:
        return ["❌ DNSSEC imzası YANLIŞDIR."]
    except Exception as e:
        return [f"DNSSEC yoxlama xətası: {e}"]

def check_spoofing(domain, record_type='A'):
    servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    results = []
    values = []

    for server in servers:
        try:
            query = dns.message.make_query(domain, record_type)
            response = dns.query.udp(query, server, timeout=3)
            for answer in response.answer:
                for item in answer.items:
                    result = item.to_text()
                    results.append((server, result))
                    values.append(result)
        except Exception:
            results.append((server, "Xəta və ya cavab yoxdur."))

    unique = set(values)
    status = "✅ Uyğun cavablar (spoofing riski görünmür)" if len(unique) <= 1 else "⚠️ Müxtəlif cavablar! Spoofing riski ola bilər."
    return results, status


def check_dane(domain):
    dane_domain = f"_443._tcp.{domain.strip('.')}"
    try:
        answers = dns.resolver.resolve(dane_domain, 'TLSA')
        return [r.to_text() for r in answers]
    except:
        return []


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    dnssec_results = []
    dnssec_verify_result = []
    spoofing_results = []
    spoofing_status = ""
    dane_records = []
    score = 0
    record_type = 'A'

    if request.method == "POST":
        domain = request.form.get("domain")
        record_type = request.form.get("record_type")

        results = resolve_with_cache(domain, record_type)
        dnssec_results = resolve_dnssec(domain)
        dnssec_verify_result = verify_dnssec(domain)
        dane_records = check_dane(domain)
        spoofing_results, spoofing_status = check_spoofing(domain, record_type)

        dnssec_enabled = any("DNSKEY" in r for r in dnssec_results)
        dnssec_valid = any("etibarlıdır" in r.lower() for r in dnssec_verify_result)
        spoofing_ok = "⚠️" not in spoofing_status


    return render_template("index.html",
        results=results,
        dnssec_results=dnssec_results,
        dnssec_verify_result=dnssec_verify_result,
        spoofing_results=spoofing_results,
        spoofing_status=spoofing_status,
        dane_records=dane_records,
        record_type=record_type
    )

if __name__ == "__main__":
    app.run(debug=True)