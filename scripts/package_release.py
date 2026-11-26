"""Build distributable archives from a tested Windows EXE and tracked server sources."""

import base64
import argparse
import hashlib
import io
import json
import os
import shutil
import tempfile
import subprocess
import tarfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]


def signing_info(exe, project_key=False, publisher_sha256=None):
    command = """
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $sig = Get-AuthenticodeSignature -LiteralPath $env:VIPNET_RELEASE_FILE
        $name = $null
        if ($sig.SignerCertificate) { $name = $sig.SignerCertificate.GetNameInfo('SimpleName',$false) }
        $pin = $null
        if ($sig.SignerCertificate) {
            $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($sig.SignerCertificate.RawData)
            $pin = [BitConverter]::ToString($hash).Replace('-','').ToLowerInvariant()
        }
        @{status=$sig.Status.ToString(); signer=$pin; publisher=$name; timestamped=($null -ne $sig.TimeStamperCertificate)} |
            ConvertTo-Json -Compress
    """
    env = dict(os.environ, VIPNET_RELEASE_FILE=str(exe))
    env.pop("PSMODULEPATH", None)  # Windows PowerShell must load its own built-in security module.
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.check_output([powershell,"-NoProfile","-NonInteractive","-Command",command],env=env)
    status = json.loads(result.decode("utf-8-sig"))
    thumbprint = status.pop("signer", None)
    if publisher_sha256 and status["status"] == "Valid" and thumbprint != publisher_sha256:
        raise ValueError("Unexpected Windows publisher")
    if project_key and status["status"] in {"UnknownError", "NotTrusted", "Valid"}:
        import lief  # Release verification dependency, independent of the Windows trusted-root store.
        der = base64.b64decode((ROOT / "client/windows/project-signer.b64").read_text().strip(), validate=True)
        pe = lief.PE.parse(str(exe))
        if (thumbprint not in {hashlib.sha256(der).hexdigest(), publisher_sha256} or not thumbprint or not pe or
                pe.verify_signature() != lief.PE.Signature.VERIFICATION_FLAGS.OK or not status["timestamped"]):
            raise ValueError("Invalid project Authenticode signature, unexpected signer or missing timestamp")
        if status["status"] != "Valid":
            if thumbprint != hashlib.sha256(der).hexdigest():
                raise ValueError("Public publisher certificate is not trusted by Windows")
            status["status"] = "ProjectSigned"
        return status
    if publisher_sha256 and (status["status"] != "Valid" or thumbprint != publisher_sha256):
        raise ValueError("Unexpected Windows publisher")
    if status["status"] not in {"NotSigned","Valid"}:
        raise ValueError(f"Windows signature verification failed: {status['status']}")
    return status


def public_notice(member):
    member.uid = member.gid = member.mtime = 0
    member.uname = member.gname = ""
    member.mode = 0o644
    return member


def package(exe, output, json_license, zlib_license, gui=None, web=None, require_signature=False, project_proof=False, publisher_sha256=None):
    gui = gui or exe.with_name("VIP-NET-Diagnostyka.exe")
    with tempfile.TemporaryDirectory(prefix="vipnet-release-") as folder:
        # Verify and package immutable copies in the publishing user's private temp directory.
        staging = Path(folder)
        private_exe, private_gui = staging/"vipnet-mtr.exe", staging/"VIP-NET-Diagnostyka.exe"
        shutil.copyfile(exe, private_exe)
        shutil.copyfile(gui, private_gui)
        _package_snapshot(private_exe, private_gui, output, json_license, zlib_license, web,
                          require_signature, project_proof or require_signature, publisher_sha256)


def _package_snapshot(exe, gui, output, json_license, zlib_license, web, require_signature, project_proof, publisher_sha256):
    if require_signature and not publisher_sha256:
        raise ValueError("A pinned public publisher certificate SHA-256 is required")
    def pe_version(path):
        return subprocess.check_output(["powershell.exe","-NoProfile","-NonInteractive","-Command",
            "(Get-Item -LiteralPath $env:VIPNET_RELEASE_FILE).VersionInfo.ProductVersion"],
            env=dict(os.environ, VIPNET_RELEASE_FILE=str(path)), text=True).strip()
    version = pe_version(exe)
    if version != "1.0.0":
        raise ValueError("the tested v1.0.0 executable is required")
    web = web or ROOT / "frontend/dist"
    if not (web / "index.html").is_file() or not any((web / "assets").glob("*.js")):
        raise ValueError("build the portal with pnpm run build first")
    if not gui.is_file():
        raise ValueError("build the native Windows GUI first")
    gui_signature = signing_info(gui, project_proof, publisher_sha256)
    cli_signature = signing_info(exe, project_proof, publisher_sha256)
    if require_signature and not all(s["status"]=="Valid" and s["publisher"] and s["timestamped"]
                                     for s in (gui_signature,cli_signature)):
        raise ValueError("A valid timestamped publisher signature is required on both EXEs")
    output.mkdir(parents=True, exist_ok=False)
    metadata = output / "windows-release.json"
    info = dict(version=version, authenticode=gui_signature, platform="windows-x64",
                size=gui.stat().st_size, sha256=hashlib.sha256(gui.read_bytes()).hexdigest())
    if project_proof:
        if any(sig["status"] not in {"Valid","ProjectSigned"} for sig in (gui_signature,cli_signature)):
            raise ValueError("Both binaries must carry verified Authenticode signatures")
        gui_version = pe_version(gui)
        if gui_version != version:
            raise ValueError("GUI and CLI versions differ")
        info["proof"] = subprocess.check_output(["pwsh","-NoProfile","-NonInteractive","-File",
            str(ROOT/"scripts/sign_project_release.ps1"),"-ManifestFromStdin"], input=json.dumps(info), text=True).strip()
    metadata.write_text(json.dumps(info, ensure_ascii=False)+"\n", encoding="utf-8")
    win = output / f"vipnet-windows-x64-{version}.zip"
    with ZipFile(win, "x", compression=ZIP_DEFLATED) as archive:
        for source, name in (
            (ROOT / "LICENSE", "LICENSE"),
            (exe, "vipnet-mtr.exe"),
            (gui, "VIP-NET-Diagnostyka.exe"),
            (ROOT / "deploy/windows-portable.md", "README.md"),
            (ROOT / "scripts/import_oui.py", "import_oui.py"),
            (json_license, "licenses/nlohmann-json.txt"),
            (zlib_license, "licenses/zlib.txt"),
        ):
            archive.write(source, name)
    tracked = (
        subprocess.check_output(
            [
                "git",
                "ls-files",
                "-z",
                "--",
                "server",
                "rules",
                "contracts/v1",
                "deploy/linux",
                "measurement-node",
                "scripts/wan_client.py",
            ],
            cwd=ROOT,
        )
        .decode("utf-8")
        .split("\0")
    )
    server = output / f"vipnet-server-{version}.tar.gz"
    assets = {p.relative_to(web).as_posix():p for p in sorted(web.rglob("*")) if p.is_file()}
    assets["VIP-NET-Diagnostyka.exe"] = gui
    assets["windows-release.json"] = metadata
    notices = {"LICENSE": ROOT / "LICENSE", "licenses/zlib.txt": zlib_license,
               "licenses/nlohmann-json.txt": json_license, "licenses/vue.txt": ROOT / "licenses/vue.txt"}
    with tarfile.open(server, "x:gz") as archive:
        for name, source in notices.items():
            archive.add(source, arcname=name, recursive=False, filter=public_notice)
        for key, source in assets.items():
            data = source.read_bytes()
            member = tarfile.TarInfo("frontend/dist/" + key)
            member.mode, member.size = 0o644, len(data)
            archive.addfile(member, io.BytesIO(data))
        for name in sorted(filter(None, tracked)):
            path = Path(name)
            if path.name.startswith("test_") or path.suffix not in {
                ".py",
                ".md",
                ".sql",
                ".ini",
                ".mako",
                ".json",
                ".txt",
                ".service",
                ".timer",
                ".sh",
                ".conf",
            }:
                continue
            source = ROOT / path
            data = source.read_bytes().replace(b"\r\n", b"\n")
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if path.suffix == ".sh" or name == "measurement-node/linux_icmp.py" else 0o644
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    with ZipFile(win) as archive:
        if archive.testzip() or archive.read("vipnet-mtr.exe") != exe.read_bytes():
            raise ValueError("invalid Windows archive")
    with tarfile.open(server) as archive:
        members = archive.getnames()
        for required in (
            "server/api.py",
            "server/requirements.txt",
            "server/migrations/versions/v051.py",
            "frontend/dist/VIP-NET-Diagnostyka.exe",
            "frontend/dist/windows-release.json",
            "server/portal.py",
            "server/game-profiles.json",
            "measurement-node/transfer.py",
            "contracts/v1/throughput.schema.json",
            "contracts/v1/inventory.schema.json",
            *notices,
            "rules/mtr.py",
        ):
            if required not in members:
                raise ValueError(f"missing {required}")
        for member in members:
            if member.startswith("frontend/dist/"):
                expected = assets[member.removeprefix("frontend/dist/")].read_bytes()
            elif member in notices:
                expected = notices[member].read_bytes()
            else:
                expected = (ROOT / member).read_bytes().replace(b"\r\n", b"\n")
            if archive.extractfile(member).read() != expected:
                raise ValueError(f"invalid server archive member {member}")
    public_exe = output / "VIP-NET-Diagnostyka.exe"
    public_exe.write_bytes(gui.read_bytes())
    checksums = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (win, server, public_exe)}
    (output / "SHA256SUMS.txt").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in checksums.items()), encoding="utf-8"
    )
    print(json.dumps(checksums))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ("exe", "output", "json-license", "zlib-license"):
        p.add_argument("--" + flag, required=True, type=Path)
    p.add_argument("--require-signature", action="store_true")
    p.add_argument("--project-proof", action="store_true")
    p.add_argument("--publisher-sha256", help="Pinned SHA-256 of the approved public Authenticode certificate (DER)")
    a = p.parse_args()
    package(
        a.exe.resolve(strict=True),
        a.output.resolve(),
        a.json_license.resolve(strict=True),
        a.zlib_license.resolve(strict=True),
        require_signature=a.require_signature, project_proof=a.project_proof,
        publisher_sha256=a.publisher_sha256.lower() if a.publisher_sha256 else None,
    )
