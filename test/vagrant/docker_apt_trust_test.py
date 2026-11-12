#!/usr/bin/env python3
"""Spec for vagrant/bootstrap.sh Docker apt trust.

These tests execute vagrant/bootstrap.sh as root, the way the Vagrant shell
provisioner does. A local TLS server answers for download.docker.com so the
script's curl | apt-key add and apt-get upgrade/install run against a
repository this process controls.

They are expected to fail while the script trusts whatever key the download
host returns. They pass once a substituted key is not installed, is not added
to the global apt trust store, and a later response from the same URL cannot
replace a key the script already accepted.

Exit 0: the script refused the substituted key.
Exit 1: the substituted key was trusted or its package ran as root.
Exit 2: the harness could not exercise the script.
"""

import gzip
import hashlib
import http.server
import os
import shutil
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "vagrant" / "bootstrap.sh"
VAGRANTFILE = ROOT / "vagrant" / "Vagrantfile"
DEFAULT_CONF = ROOT / "vagrant" / "default.conf"
DOCKER_PUB = Path(__file__).resolve().parent / "fixtures" / "docker-release-ce-public.asc"
MARKER_DIR = "/var/tmp/juice-shop-apt-attack"
HOST = "download.docker.com"


class HarnessError(Exception):
    pass


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def capture(cmd, **kwargs):
    return subprocess.run(
        cmd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    ).stdout


def enter_namespace():
    if os.environ.get("APT_TRUST_NS") == "1":
        return
    os.environ["APT_TRUST_NS"] = "1"
    cmd = [
        "unshare",
        "--mount",
        "--net",
        "--pid",
        "--fork",
        "--mount-proc",
        "--propagation",
        "private",
        sys.executable,
        str(Path(__file__).resolve()),
    ]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n", *cmd]
    os.execvp(cmd[0], cmd)


def openssl_cert(work: Path):
    ca_key = work / "ca.key"
    ca_crt = work / "ca.crt"
    srv_key = work / "srv.key"
    srv_csr = work / "srv.csr"
    srv_crt = work / "srv.crt"
    ext = work / "srv.ext"
    run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_crt), "-days", "2",
            "-subj", "/CN=Juice Shop Apt Trust Test CA",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(srv_key), "-out", str(srv_csr),
            "-subj", f"/CN={HOST}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ext.write_text(
        "subjectAltName=DNS:download.docker.com\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
    )
    run(
        [
            "openssl", "x509", "-req", "-in", str(srv_csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(srv_crt), "-days", "2", "-extfile", str(ext),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return ca_crt, srv_crt, srv_key


def generate_attacker():
    home = Path("/mnt/ovroot/attacker-gpg")
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(mode=0o700)
    env = os.environ.copy()
    env["GNUPGHOME"] = str(home)
    run(
        [
            "gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
            "--quick-gen-key", "Apt Trust Test <apt-trust-test@example.invalid>",
            "rsa4096", "sign", "0",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    public = capture(["gpg", "--batch", "--armor", "--export"], env=env).encode()
    fpr = ""
    shown = capture(["gpg", "--batch", "--show-keys", "--with-colons"], env=env, input=public.decode())
    for line in shown.splitlines():
        if line.startswith("fpr:"):
            fpr = line.split(":")[9]
            break
    if not fpr:
        raise HarnessError("attacker key had no fingerprint")
    return home, public, fpr


def build_deb(dest: Path, name: str, version: str, marker: str | None, docker_stub: bool):
    stage = dest.parent / f"stage-{name}-{version}"
    if stage.exists():
        shutil.rmtree(stage)
    debian = stage / "DEBIAN"
    debian.mkdir(parents=True)
    (debian / "control").write_text(
        textwrap.dedent(
            f"""\
            Package: {name}
            Version: {version}
            Architecture: amd64
            Maintainer: Apt Trust Test <apt-trust-test@example.invalid>
            Description: provision trust probe
            """
        )
    )
    if marker:
        (debian / "postinst").write_text(
            "#!/bin/sh\n"
            f"mkdir -p {MARKER_DIR}\n"
            f"id -u > {MARKER_DIR}/{marker}\n"
            f"printf '%s\\n' \"$0\" >> {MARKER_DIR}/{marker}\n"
        )
        os.chmod(debian / "postinst", 0o755)
    if docker_stub:
        binary = stage / "usr" / "bin"
        binary.mkdir(parents=True)
        (binary / "docker").write_text(
            "#!/bin/sh\n"
            f"mkdir -p {MARKER_DIR}\n"
            f"printf '%s\\n' \"$*\" >> {MARKER_DIR}/docker-argv\n"
            "exit 0\n"
        )
        os.chmod(binary / "docker", 0o755)
    cmd = ["dpkg-deb"]
    help_text = subprocess.run(["dpkg-deb", "--help"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    if "--root-owner-group" in help_text:
        cmd.append("--root-owner-group")
    cmd += ["-b", str(stage), str(dest)]
    run(cmd, stdout=subprocess.DEVNULL)


def sha256_file(path: Path):
    digest = hashlib.sha256()
    data = path.read_bytes()
    digest.update(data)
    return digest.hexdigest(), len(data)


def md5_file(path: Path):
    data = path.read_bytes()
    return hashlib.md5(data).hexdigest(), len(data)


def write_repo(repo: Path, debs: list[Path], signer_home: Path, codename: str):
    pool = repo / "pool"
    packages_dir = repo / "dists" / codename / "stable" / "binary-amd64"
    pool.mkdir(parents=True)
    packages_dir.mkdir(parents=True)
    paragraphs = []
    for deb in debs:
        shutil.copy(deb, pool / deb.name)
        control = capture(["dpkg-deb", "-f", str(deb)])
        sha, size = sha256_file(pool / deb.name)
        md5, _ = md5_file(pool / deb.name)
        paragraphs.append(
            control.strip()
            + "\n"
            + f"Filename: pool/{deb.name}\n"
            + f"Size: {size}\n"
            + f"MD5sum: {md5}\n"
            + f"SHA256: {sha}\n"
        )
    packages = ("\n".join(paragraphs) + "\n").encode()
    (packages_dir / "Packages").write_bytes(packages)
    with gzip.open(packages_dir / "Packages.gz", "wb") as handle:
        handle.write(packages)
    entries = []
    for rel in (
        f"stable/binary-amd64/Packages",
        f"stable/binary-amd64/Packages.gz",
    ):
        path = repo / "dists" / codename / rel
        sha, size = sha256_file(path)
        md5, _ = md5_file(path)
        entries.append((rel, sha, md5, size))
    release = repo / "dists" / codename / "Release"
    lines = [
        "Origin: Docker",
        "Label: Docker",
        f"Suite: {codename}",
        f"Codename: {codename}",
        "Architectures: amd64",
        "Components: stable",
        "Date: Thu, 01 Jan 2026 00:00:00 UTC",
        "Valid-Until: Thu, 01 Jan 2036 00:00:00 UTC",
        "MD5Sum:",
    ]
    for rel, _sha, md5, size in entries:
        lines.append(f" {md5} {size} {rel}")
    lines.append("SHA256:")
    for rel, sha, _md5, size in entries:
        lines.append(f" {sha} {size} {rel}")
    release.write_text("\n".join(lines) + "\n")
    env = os.environ.copy()
    env["GNUPGHOME"] = str(signer_home)
    run(
        [
            "gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
            "--digest-algo", "SHA256", "--detach-sign", "--armor",
            "--output", str(release.with_name("Release.gpg")), str(release),
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    run(
        [
            "gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
            "--digest-algo", "SHA256", "--clearsign",
            "--output", str(release.with_name("InRelease")), str(release),
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class KeyServer(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        self.server.paths.append(path)
        if path == "/linux/ubuntu/gpg":
            body = self.server.next_key()
            self._send(200, "application/pgp-keys", body)
            return
        prefix = "/linux/ubuntu/"
        if path.startswith(prefix):
            rel = path[len(prefix):]
            file_path = self.server.repo / rel
            if file_path.is_file():
                self._send(200, "application/octet-stream", file_path.read_bytes())
                return
        self._send(404, "text/plain", b"not found\n")

    def _send(self, status, content_type, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def serve(repo: Path, keys: list[bytes], cert: Path, key: Path):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 443), KeyServer)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.repo = repo
    httpd.keys = keys
    httpd.key_index = 0
    httpd.paths = []

    def next_key():
        idx = httpd.key_index
        httpd.key_index += 1
        if idx >= len(httpd.keys):
            idx = len(httpd.keys) - 1
        return httpd.keys[idx]

    httpd.next_key = next_key
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", 443), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    else:
        raise HarnessError("TLS stand-in did not listen on port 443")
    return httpd


def mount_sandbox():
    base = Path("/mnt/ovroot/sandbox")
    if base.exists():
        subprocess.run(["umount", "-l", str(base / "merged")], check=False)
        subprocess.run(["umount", "-l", str(base / "lower")], check=False)
        shutil.rmtree(base, ignore_errors=True)
    for name in ("upper", "work", "lower", "merged", "shared"):
        (base / name).mkdir(parents=True)
    run(["mount", "--bind", "/", str(base / "lower")])
    run(
        [
            "mount", "-t", "overlay", "overlay",
            "-o", f"lowerdir={base / 'lower'},upperdir={base / 'upper'},workdir={base / 'work'}",
            str(base / "merged"),
        ]
    )
    merged = base / "merged"
    run(["mount", "-t", "proc", "proc", str(merged / "proc")])
    run(["mount", "--bind", "/dev", str(merged / "dev")])
    run(["mount", "-t", "devpts", "devpts", str(merged / "dev" / "pts")])
    run(["mount", "-t", "sysfs", "sysfs", str(merged / "sys")])
    run(["mount", "-t", "tmpfs", "tmpfs", str(merged / "run")])
    run(["mount", "-t", "tmpfs", "tmpfs", str(merged / "tmp")])
    run(["mount", "-t", "tmpfs", "tmpfs", str(merged / "var" / "run")])
    (merged / "shared").mkdir(exist_ok=True)
    run(["mount", "--bind", str(base / "shared"), str(merged / "shared")])
    return base


def unmount_sandbox(base: Path):
    merged = base / "merged"
    for rel in ("shared", "var/run", "tmp", "run", "sys", "dev/pts", "dev", "proc"):
        subprocess.run(["umount", "-l", str(merged / rel)], check=False)
    subprocess.run(["umount", "-l", str(merged)], check=False)
    subprocess.run(["umount", "-l", str(base / "lower")], check=False)


INSIDE = r"""#!/bin/bash
set +e
dump_trust() {
  local out="$1"
  : > "$out"
  shopt -s nullglob
  local f
  for f in /etc/apt/trusted.gpg /etc/apt/trusted.gpg~ /etc/apt/trusted.gpg.d/*; do
    [ -f "$f" ] || continue
    printf 'FILE %s\n' "$f" >> "$out"
    gpg --batch --show-keys --with-colons "$f" >> "$out" 2>/dev/null
  done
}
dump_tree() {
  local out="$1"
  : > "$out"
  if [ -d /etc/apt/keyrings ]; then
    find /etc/apt/keyrings -type f | sort >> "$out"
  fi
  find /etc/apt/keyrings /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d /etc/apt/sources.list.d -type f 2>/dev/null | sort | while read -r f; do
    printf 'FILE %s\n' "$f" >> "$out"
    gpg --batch --show-keys --with-colons "$f" >> "$out" 2>/dev/null
  done
}
mkdir -p /tmp/juice-shop /usr/local/share/ca-certificates /etc/apt/sources.list.d /etc/apt/apt.conf.d
cp /shared/default.conf /tmp/juice-shop/default.conf
cp /shared/ca.crt /usr/local/share/ca-certificates/apt-trust-test.crt
update-ca-certificates > /shared/update-ca.log 2>&1
printf '\n127.0.0.1 download.docker.com\n' >> /etc/hosts
: > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*
printf 'Acquire::ForceIPv4 "true";\nAPT::Get::Assume-Yes "true";\nAPT::Sandbox::User "root";\n' > /etc/apt/apt.conf.d/99-trust-test
export DEBIAN_FRONTEND=noninteractive
dpkg -i /shared/probe_1.0.deb > /shared/probe-install.log 2>&1
sudo -n true > /shared/sudo.log 2>&1
echo $? > /shared/sudo.ec
dump_trust /shared/trust-before.txt
dpkg-query -W -f '${Package} ${Version}\n' juice-shop-provision-probe docker-ce apache2 > /shared/pkg-before.txt 2>/dev/null
find /etc/apt/sources.list.d /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d /etc/apt/keyrings -type f 2>/dev/null | sort > /shared/apt-files-before.txt
timeout 180 sh /shared/bootstrap.sh > /shared/bootstrap.log 2>&1
echo $? > /shared/bootstrap.ec
dump_trust /shared/trust-after.txt
dump_tree /shared/tree-after.txt
dpkg-query -W -f '${Package} ${Version}\n' juice-shop-provision-probe docker-ce apache2 > /shared/pkg-after.txt 2>/dev/null
find /etc/apt/sources.list.d /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d /etc/apt/keyrings -type f 2>/dev/null | sort > /shared/apt-files-after.txt
if [ -d /var/tmp/juice-shop-apt-attack ]; then
  cp -a /var/tmp/juice-shop-apt-attack /shared/markers
fi
if [ -f /etc/apt/sources.list.d/docker-ce.list ]; then
  cp /etc/apt/sources.list.d/docker-ce.list /shared/docker-ce.list
fi
"""


def fprs_from_dump(text: str):
    found = set()
    for line in text.splitlines():
        if line.startswith("fpr:"):
            parts = line.split(":")
            if len(parts) > 9 and parts[9]:
                found.add(parts[9])
    return found


def pkg_map(text: str):
    found = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            found[parts[0]] = parts[1]
    return found


def read_shared(shared: Path, name: str) -> str:
    path = shared / name
    if not path.exists():
        return ""
    return path.read_text(errors="replace")


def run_scenario(name: str, keys: list[bytes], signer_home: Path, attacker_fpr: str, docker_fpr: str, mode: str, codename: str, ca_crt: Path, srv_crt: Path, srv_key: Path):
    work = Path("/mnt/ovroot") / name
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    debs_dir = work / "debs"
    debs_dir.mkdir()
    probe_old = debs_dir / "juice-shop-provision-probe_1.0_amd64.deb"
    probe_new = debs_dir / "juice-shop-provision-probe_2.0_amd64.deb"
    docker_deb = debs_dir / "docker-ce_99.0.0_amd64.deb"
    apache_deb = debs_dir / "apache2_99.0.0_amd64.deb"
    build_deb(probe_old, "juice-shop-provision-probe", "1.0", None, False)
    build_deb(probe_new, "juice-shop-provision-probe", "2.0", "upgrade", False)
    build_deb(docker_deb, "docker-ce", "99.0.0", "docker-ce", True)
    build_deb(apache_deb, "apache2", "99.0.0", "apache2", False)
    repo = work / "repo"
    write_repo(repo, [probe_new, docker_deb, apache_deb], signer_home, codename)
    base = mount_sandbox()
    shared = base / "shared"
    try:
        shutil.copy(BOOTSTRAP, shared / "bootstrap.sh")
        shutil.copy(DEFAULT_CONF, shared / "default.conf")
        shutil.copy(ca_crt, shared / "ca.crt")
        shutil.copy(probe_old, shared / "probe_1.0.deb")
        (shared / "inside.sh").write_text(INSIDE)
        os.chmod(shared / "inside.sh", 0o755)
        httpd = serve(repo, keys, srv_crt, srv_key)
        try:
            completed = subprocess.run(
                ["chroot", str(base / "merged"), "bash", "/shared/inside.sh"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        finally:
            httpd.shutdown()
            httpd.server_close()
        gpg_hits = [p for p in httpd.paths if p.split("?", 1)[0] == "/linux/ubuntu/gpg"]
        problems = []
        notes = []
        if completed.returncode != 0:
            raise HarnessError(f"{name}: chroot setup failed: {completed.stderr[-2000:]}")
        if read_shared(shared, "sudo.ec").strip() not in ("0", ""):
            raise HarnessError(f"{name}: sudo -n failed inside the sandbox\n{read_shared(shared, 'sudo.log')}")
        if not gpg_hits:
            raise HarnessError(
                f"{name}: bootstrap.sh never requested the Docker signing key\n"
                f"{read_shared(shared, 'bootstrap.log')[-2000:]}"
            )
        before = fprs_from_dump(read_shared(shared, "trust-before.txt"))
        after = fprs_from_dump(read_shared(shared, "trust-after.txt"))
        added_global = after - before
        tree = read_shared(shared, "tree-after.txt")
        tree_fprs = fprs_from_dump(tree)
        pkg_before = pkg_map(read_shared(shared, "pkg-before.txt"))
        pkg_after = pkg_map(read_shared(shared, "pkg-after.txt"))
        markers = {}
        marker_root = shared / "markers"
        if marker_root.exists():
            for marker in marker_root.iterdir():
                if marker.is_file():
                    markers[marker.name] = marker.read_text(errors="replace").strip()
        source_list = read_shared(shared, "docker-ce.list")
        files_before = set(read_shared(shared, "apt-files-before.txt").splitlines())
        files_after = set(read_shared(shared, "apt-files-after.txt").splitlines())
        new_files = sorted(files_after - files_before)
        notes.append(f"gpg requests: {len(gpg_hits)}")
        notes.append(f"bootstrap exit: {read_shared(shared, 'bootstrap.ec').strip()}")
        notes.append(f"global fingerprints added: {', '.join(sorted(added_global)) or 'none'}")
        if markers:
            notes.append(f"maintainer markers: {markers}")
        if source_list:
            notes.append(f"docker-ce.list: {source_list.strip()}")
        if markers:
            problems.append(f"maintainer script ran as root: {markers}")
        if pkg_after.get("docker-ce") and pkg_after.get("docker-ce") != pkg_before.get("docker-ce"):
            problems.append(f"docker-ce installed at version {pkg_after.get('docker-ce')}")
        if pkg_after.get("apache2") == "99.0.0" and pkg_before.get("apache2") != "99.0.0":
            problems.append("apache2 replaced by the substituted repository package")
        if pkg_after.get("juice-shop-provision-probe") == "2.0":
            problems.append("apt-get upgrade installed the substituted probe package")
        if attacker_fpr in added_global or attacker_fpr in tree_fprs:
            problems.append(f"attacker key {attacker_fpr} is in the apt trust configuration")
        if added_global:
            problems.append(
                "global apt trust store gained "
                + ", ".join(sorted(added_global))
            )
        if mode == "hostile" and "/etc/apt/sources.list.d/docker-ce.list" in new_files:
            problems.append("docker apt source was written for a key that is not pinned")
        if mode == "refetch" and source_list and "signed-by=" not in source_list:
            problems.append("docker apt source does not bind the repository to a keyring file")
        if mode == "refetch" and attacker_fpr in tree_fprs:
            problems.append("a later key response was trusted")
        log_tail = read_shared(shared, "bootstrap.log")[-1500:]
        return {"name": name, "problems": problems, "notes": notes, "log_tail": log_tail}
    finally:
        unmount_sandbox(base)


def main():
    enter_namespace()
    if os.geteuid() != 0:
        print("harness: not root inside the namespace", file=sys.stderr)
        return 2
    for tool in ("gpg", "openssl", "dpkg-deb", "curl", "apt-get", "apt-key", "lsb_release", "update-ca-certificates"):
        if shutil.which(tool) is None:
            print(f"harness: missing {tool}", file=sys.stderr)
            return 2
    if not BOOTSTRAP.is_file() or not DOCKER_PUB.is_file():
        print("harness: bootstrap.sh or Docker public key fixture missing", file=sys.stderr)
        return 2
    if "privileged: false" in VAGRANTFILE.read_text():
        print("harness: Vagrantfile forces an unprivileged shell provisioner", file=sys.stderr)
        return 2
    run(["ifconfig", "lo", "up"])
    Path("/mnt/ovroot").mkdir(exist_ok=True)
    if not Path("/mnt/ovroot").is_mount():
        run(["mount", "-t", "tmpfs", "tmpfs", "/mnt/ovroot"])
    try:
        ca_crt, srv_crt, srv_key = openssl_cert(Path("/mnt/ovroot"))
        signer_home, attacker_pub, attacker_fpr = generate_attacker()
        docker_pub = DOCKER_PUB.read_bytes()
        docker_fpr = ""
        shown = capture(["gpg", "--batch", "--show-keys", "--with-colons", str(DOCKER_PUB)])
        for line in shown.splitlines():
            if line.startswith("fpr:"):
                docker_fpr = line.split(":")[9]
                break
        if not docker_fpr:
            raise HarnessError("Docker public key fixture has no fingerprint")
        codename = capture(["lsb_release", "-cs"]).strip()
        scenarios = [
            ("substituted_key_not_installed", [attacker_pub], "hostile"),
            ("refetch_does_not_trust_later_key", [docker_pub, attacker_pub], "refetch"),
        ]
        failures = 0
        for name, keys, mode in scenarios:
            print(f"== {name} ==")
            result = run_scenario(
                name, keys, signer_home, attacker_fpr, docker_fpr, mode, codename, ca_crt, srv_crt, srv_key
            )
            for note in result["notes"]:
                print(f"  {note}")
            if result["problems"]:
                failures += 1
                for problem in result["problems"]:
                    print(f"FAIL {name}: {problem}")
                print(result["log_tail"])
            else:
                print(f"PASS {name}")
        if failures:
            print(f"{failures} scenario(s) trusted a substituted Docker apt key")
            return 1
        print("substituted Docker apt key was not trusted")
        return 0
    except HarnessError as exc:
        print(f"harness: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as exc:
        print(f"harness: command failed: {exc.cmd}", file=sys.stderr)
        if exc.stderr:
            print(exc.stderr[-2000:], file=sys.stderr)
        sys.exit(2)
