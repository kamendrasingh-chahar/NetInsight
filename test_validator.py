from utils.validators import is_valid_domain

tests = [
    "google.com",
    "github.com",
    "mail.google.com",
    "google",
    "http://google.com",
    "!!!",
]

for domain in tests:
    print(domain, "->", is_valid_domain(domain))