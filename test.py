import dns.resolver

def verify_mx(
    domain: str
):
    domain_name = domain.lower()
    valid_mx_records = ['smtp1.minutemail.co']

    try:
        records = dns.resolver.resolve(domain_name, 'MX')
        mx_hosts = [record.exchange.to_text(omit_final_dot=True).lower() for record in records]

        return all(mx in valid_mx_records for mx in mx_hosts)
    except Exception as e:
        print(f"Failed to get MX records for {domain_name}: {e}")

    return False


def verify_txt(
        domain: str,
        txt_verification: str,
):
    domain_name = domain.lower()
    try:
        records = dns.resolver.resolve(domain_name, 'TXT')
        for r in records:
            if txt_verification in r.to_text():
                return True
    except Exception as e:
        print(f"Failed to get TXT records for {domain_name}: {e}")

    return False

if __name__ == '__main__':
    print(verify_txt("gymbro.ca", "minutemail-0J1o57zNy6ykuBNe"))
    print(verify_mx("gymbro.ca"))