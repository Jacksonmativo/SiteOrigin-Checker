import ssl
import socket

# Test that your checker properly rejects invalid certs
test_cases = [
    ('expired.badssl.com', 443),
    ('wrong.host.badssl.com', 443),
    ('self-signed.badssl.com', 443),
    ('untrusted-root.badssl.com', 443)
]

for host, port in test_cases:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"{host}: {ssock.version()}")
    except ssl.SSLError as e:
        print(f"{host}: Properly rejected - {e}")