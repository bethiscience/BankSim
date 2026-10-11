"""Application entry point.

  python app.py demo                 run every scenario and print the JSON decisions
  python app.py request '<json>'     send one request
  python app.py serve --port 8000    tiny stdlib HTTP API:  POST /v1/inspect

Dashboard (separate process, same SQLite audit DB):  streamlit run dashboard.py
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config
from demo_scenarios import SCENARIOS
from firewall import Firewall


def run_demo() -> None:
    fw = Firewall()
    for name, req in SCENARIOS.items():
        r = fw.handle(req)
        print(f"\n# {name}")
        print(json.dumps(json.loads(r.model_dump_json()), indent=2))
    fw.hell.drain(10)
    print("\naudit chain intact:", fw.audit.verify_chain()[0])
    print(json.dumps(fw.audit.stats(), indent=2))


def make_handler(fw: Firewall):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/v1/inspect":
                return self._send(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n > config.MAX_RAW_BYTES:
                return self._send(413, {"error": "request too large"})
            self._send(200, json.loads(fw.handle(self.rfile.read(n)).model_dump_json()))

        def _send(self, code, body):
            out = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass
    return H


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo")
    rq = sub.add_parser("request"); rq.add_argument("json")
    sv = sub.add_parser("serve"); sv.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    if a.cmd == "demo":
        run_demo()
    elif a.cmd == "request":
        fw = Firewall()
        print(fw.handle(a.json).model_dump_json(indent=2))
        fw.hell.drain(5)
    else:
        fw = Firewall()
        print(f"BankSim firewall listening on http://127.0.0.1:{a.port}/v1/inspect")
        ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(fw)).serve_forever()
