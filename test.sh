#!/usr/bin/env bash
# Offline integration-runner contracts. Real released-host tests are separate.
set -euo pipefail
cd "$(dirname "$0")"
python_bin=${PYTHON:-python3}
command -v "$python_bin" >/dev/null || python_bin=python
"$python_bin" -B tests/integration-test.py
"$python_bin" -B tests/example-portability-test.py
"$python_bin" -m py_compile scripts/integration-run.py scripts/released-hosts.py scripts/traffic-check.py integration/traffic-client.py

if command -v lmscript >/dev/null 2>&1; then
  ver="$(lmscript --version 2>/dev/null || true)"
  if "$python_bin" - "$ver" <<'PYVER'
import re, sys
m = re.search(r'\b(\d+)\.(\d+)\.(\d+)\b', sys.argv[1])
sys.exit(0 if m and tuple(map(int, m.groups())) >= (0, 2, 482) else 1)
PYVER
  then
    work="$(mktemp -d "${TMPDIR:-/tmp}/lmdebug-std-rest-XXXXXX")"
    trap 'rm -rf "$work"' EXIT
    cat > "$work/lmdebug-probe.schema.json" <<'JSON'
{
  "dsl.schema": 2,
  "name": "lmdebug",
  "types": {
    "Meta": {"methods": {"caps_json": [{"params": [], "returns": "string"}]}},
    "SocketSummary": {"methods": {"listening": [{"params": [], "returns": "int"}]}},
    "Net": {"methods": {
      "dns_lookup": [{"params": ["string"], "returns": "StrList"}],
      "socket_summary": [{"params": ["string"], "returns": "SocketSummary"}]
    }}
  },
  "functions": {},
  "context": {"lmdebug": "Meta", "net": "Net"}
}
JSON
    cat > "$work/std-rest-cli.lms" <<EOF_LMS
p = _lmcode_ schema="$work/lmdebug-probe.schema.json";
@"--host"
fn opt_host(x: RestExchange) -> void implements CliOption {
  x.set("host", x.query("host"));
}

@"resolve"
fn cmd_resolve(x: RestExchange) -> void implements CliCommand {
  let addrs = net.dns_lookup(x.get("host"));
  x.send(x.get("host") + ":" + str(addrs.len()));
}

@"/sockets/listening"
fn get_listening(x: RestExchange) -> void implements RestGet {
  let s = net.socket_summary("tcp");
  x.json("{\"listening\":" + str(s.listening()) + "}");
}

rest_config("session", "global");
\$return.cli_out = rest_cli(str_split("--host=localhost resolve", " "));
\$return.get_out = rest_cli(str_split("/sockets/listening", " "));
end _lmcode_
EOF_LMS
    lmscript --check "$work/std-rest-cli.lms"
    sigs="$(lmscript --lmcode-signatures "$work/lmdebug-probe.schema.json")"
    host_sigs="$(lmscript --lmcode-signatures "$work/lmdebug-probe.schema.json" --without-std)"
    echo "$sigs" | grep -qF "fn rest_cli(StrList) -> string"
    echo "$sigs" | grep -qF "method RestExchange.json(string) -> void"
    "$python_bin" - "$sigs" "$host_sigs" <<'PYSIGS'
import sys
all_s = set(sys.argv[1].splitlines())
host_s = set(sys.argv[2].splitlines())
assert len(all_s - host_s) == 226, len(all_s - host_s)
PYSIGS
    if [[ -f ../lmcode-cpp/include/dslvm.hpp ]] && command -v g++ >/dev/null 2>&1; then
      cat > "$work/host.cpp" <<'CPP'
#include "dslvm.hpp"
#include <iostream>
#include <vector>
int main(int argc, char** argv) {
  if (argc < 4 || std::string(argv[1]) != "--lmcode") return 2;
  const std::string schema = dslvm::read_file(argv[2]);
  dslvm::Registry reg;
  int64_t listening = 3;
  reg.context("lmdebug", "Meta");
  reg.context("net", "Net");
  reg.method("Meta", "caps_json", {}, "string", [](void*, dslvm::Args&) {
    return dslvm::Value::string("{}");
  });
  reg.method("SocketSummary", "listening", {}, "int", [](void* s, dslvm::Args&) {
    return dslvm::Value::integer(*static_cast<int64_t*>(s));
  });
  reg.method("Net", "dns_lookup", {"string"}, "StrList", [&reg](void*, dslvm::Args&) {
    return dslvm::Value::object("StrList", reg.std_collections().make_str_list({"127.0.0.1"}));
  });
  reg.method("Net", "socket_summary", {"string"}, "SocketSummary", [&listening](void*, dslvm::Args&) {
    return dslvm::Value::object("SocketSummary", &listening);
  });
  std::vector<std::string> files = {argv[3]};
  auto results = dslvm::InvocationResults::from_command(files);
  auto contract = dslvm::ResultContract::from_schema(schema);
  auto prog = dslvm::Program::load(dslvm::read_file(argv[3]), schema, reg);
  int dummy_meta = 0, dummy_net = 0;
  dslvm::Context ctx;
  ctx.set("lmdebug", &dummy_meta);
  ctx.set("net", &dummy_net);
  results.select(0, reg, contract);
  if (!results.dry()) prog.run(ctx, reg);
  results.complete(0);
  return results.write_frame(std::cout);
}
CPP
      g++ -std=c++17 -O1 -I../lmcode-cpp/include -I../lmcode-cpp "$work/host.cpp" -o "$work/lmdebug-host"
      cat >> "$work/std-rest-cli.lms" <<EOF_RUN
r = run_lmcode(p, {command: ["$work/lmdebug-host", "--lmcode", "$work/lmdebug-probe.schema.json", "\$DSLFILE"]});
println(json_stringify(r));
EOF_RUN
      out="$(lmscript "$work/std-rest-cli.lms")"
      echo "$out" | grep -qF '"cli_out":"localhost:1"'
      echo "$out" | grep -qF '"get_out":"{\"listening\":3}"'
    fi
  fi
fi
