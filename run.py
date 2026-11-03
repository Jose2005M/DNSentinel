from waitress import serve
from dnsentinel import create_app

if __name__ == "__main__":
    app = create_app()

    print("DNSentinel disponible en http://127.0.0.1:8080", flush=True)

    serve(
        app,
        host="127.0.0.1",
        port=8080,
        threads=4,
        max_request_body_size=8192,
        max_request_header_size=16384,
        channel_timeout=30,
        connection_limit=50,
    )