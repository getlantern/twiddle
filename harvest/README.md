# harvest

Tooling that produced the measurements behind this transport. Run everything from this directory.

```bash
go build -o ../bin/capture ./cmd/capture   && ../bin/capture 18443 testdata/out.hex
go build -o ../bin/flight  ./cmd/flight    && ../bin/flight www.google.com
go build -o ../bin/resume  ./cmd/resume    && ../bin/resume
python3 analyze.py testdata/chrome-hellos.hex
python3 compare_arms.py testdata/hh-*.hex
```

`cmd/capture` needs a locally-trusted cert:

```bash
env -u JAVA_HOME mkcert -install                                  # sudo, once per machine
cd testdata && env -u JAVA_HOME mkcert localhost 127.0.0.1 ::1    # gitignored
```

`mkcert` shells out to `keytool` and aborts if `JAVA_HOME` points at a machine with no JDK keystore;
`env -u JAVA_HOME` skips that step.

**Do not wrap the OpenSSL probes in `timeout`** — it does not exist on macOS, and the command silently
never runs, which reads as a clean negative result.
