import gradio as gr
import os
import re
import pandas as pd

import subprocess

PASS_ENV = "SSLCERT_PASS"      # keystore / key passphrase via env:SSLCERT_PASS
KEYPASS_ENV = "SSLCERT_KEYPASS"  # passphrase of the uploaded key file

def run_command(args, env_vars=None):
    """Executes a command (argv list, no shell) and returns the output log.

    Secrets (passphrases) are passed through env_vars (e.g. env:SSLCERT_PASS in
    the argv) so they never appear in the command line / process list.
    """
    env = dict(os.environ)
    if env_vars:
        env.update(env_vars)
    result = subprocess.run(args, capture_output=True, text=True, env=env)
    log = result.stdout.strip() if result.stdout else result.stderr.strip()
    if result.returncode != 0:
        log = f"{log}\n(command failed with exit code {result.returncode})"
    return log

def safe_component(name):
    """Validate a user-provided filename component (no path separators, shell metacharacters)."""
    if not name or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError(
            f"Invalid name {name!r}: use a single word without spaces or special characters"
        )
    return name

def sanitize_text(value):
    """Strip newlines and surrounding whitespace from text destined for the config file."""
    return str(value or "").replace("\r", "").replace("\n", " ").strip()

def delete_csr(default_save_location, server_name):

    server_name = safe_component(server_name)
    cnf_file=os.path.join(default_save_location,f"{server_name}.cnf")
    key_file=os.path.join(default_save_location,f"{server_name}.key")
    csr_file=os.path.join(default_save_location,f"{server_name}.csr")
    cmd = ""
    for label, path in (("cnf", cnf_file), ("key", key_file), ("csr", csr_file)):
        if os.path.isfile(path):
            os.remove(path)
            cmd = cmd + f"\n===deleted .{label} file========\nremoved {path}"
        else:
            cmd = cmd + f"\n===deleted .{label} file========\nnot found: {path}"
    return cmd,None,None,None

def create_csr(prompt,password,default_bits, default_keyfile,distinguished_name,
                req_extensions,server_name, country, state, locality,
                org, org_unit, cn, email,subjectAltName,default_save_location,dataframe):
    try:
        server_name = safe_component(server_name)
        default_keyfile = safe_component(default_keyfile)
    except ValueError as e:
        return str(e),None,None,None

    # newline injection into the config file would change openssl semantics
    dns_alt_names = [sanitize_text(n) for n in dataframe["DNS Alt Name"].tolist()]
    prompt = sanitize_text(prompt)
    default_bits = int(default_bits) if default_bits else 2048
    distinguished_name = sanitize_text(distinguished_name)
    req_extensions = sanitize_text(req_extensions)
    country = sanitize_text(country)
    state = sanitize_text(state)
    locality = sanitize_text(locality)
    org = sanitize_text(org)
    org_unit = sanitize_text(org_unit)
    cn = sanitize_text(cn)
    email = sanitize_text(email)
    subjectAltName = sanitize_text(subjectAltName)
    password = str(password or "").replace("\r", "").replace("\n", "")

    DNS=""
    for i,name in enumerate(dns_alt_names,start=1):
        if name:
            DNS=DNS+f"DNS.{i} = {name}\n"

    cnf_file_text = f"""
[req]
distinguished_name = {distinguished_name}
prompt = {prompt}
default_bits = {default_bits}
default_keyfile = {default_keyfile}
req_extensions = {req_extensions}

[req_distinguished_name]
C = {country}
ST = {state}
L = {locality}
O = {org}
OU = {org_unit}
CN = {cn}
emailAddress = {email}

[req_ext]
subjectAltName = {subjectAltName}

[alt_names]
{DNS}
"""
    cnf_file=os.path.join(default_save_location,f"{server_name}.cnf")
    key_file=os.path.join(default_save_location,f"{server_name}.key")
    csr_file=os.path.join(default_save_location,f"{server_name}.csr")
    with open(cnf_file, "w") as file:
        file.write(cnf_file_text)

    command = [
        "openssl", "req", "-new",
        "-config", cnf_file,
        "-keyout", key_file,
        "-out", csr_file,
        "-passout", f"env:{PASS_ENV}",
        "-verbose",
    ]

    output = run_command(command, {PASS_ENV: password})
    return output + f"\nyour passphrase is set as {password}",cnf_file,key_file,csr_file

def detect_format(cert_path):
    """Detect the certificate file format (PEM or DER) by inspecting the file content."""
    try:
        with open(cert_path, "rb") as f:
            content = f.read()
        if b"-----BEGIN CERTIFICATE REQUEST-----" in content:
            return "CSR"  # CSR is not a certificate; cannot be converted with x509
        if (b"-----BEGIN CERTIFICATE-----" in content
                or b"-----BEGIN PUBLIC KEY-----" in content):
            return "PEM"
        if content.startswith(b"\x30"):  # ASN.1 SEQUENCE tag typical of DER
            return "DER"
        return "unknown"
    except OSError as e:
        return f"error: {e}"

def convert_certificate(cert, new_place, new_format):
    cert_path = cert.name if cert else ""
    if not cert_path:
        return "Error: No certificate file provided.", "", ""

    detected = detect_format(cert_path)
    if detected == "CSR":
        return (
            "Error: this is a CSR, not a certificate. Convert the issued certificate instead.",
            detected,
            new_format or "",
        )
    if not new_format:
        new_format = "PEM"
    new_format = new_format.upper()

    if detected == new_format:
        return (
            f"File is already {new_format} format, no conversion needed.",
            detected,
            new_format,
        )

    new_cert_path = os.path.join(new_place, "converted_cert." + new_format.lower())
    command = [
        "openssl", "x509",
        "-in", cert_path,
        "-out", new_cert_path,
        "-outform", new_format,
    ]

    result = run_command(command)
    return f"Conversion completed: {new_cert_path}\n{result}", detected, new_format

def create_keystore(cert, key, password, platform, keystore_place, key_password):
    cert_path = cert.name if cert else ""
    key_path = key.name if key else ""

    if not cert_path or not key_path:
        return "Error: Certificate or Key file missing."
    if not password:
        return "Error: Keystore password required."

    if platform == "Windows":
        # PKCS12 is the native Windows-compatible container format
        ext = "pfx"
        options = "-legacy"  # 3DES/PKCS12 v1.0 for broad Windows/Java import
    else:
        ext = "jks"
        options = ""  # default PKCS12 output, readable by keytool/Java as JKS

    keystore_path = os.path.join(keystore_place, f"keystore.{ext}")

    command = [
        "openssl", "pkcs12", "-export",
        "-in", cert_path,
        "-inkey", key_path,
        "-out", keystore_path,
        "-password", f"env:{PASS_ENV}",
    ]
    if key_password:
        # private key file itself is passphrase-protected
        command += ["-passin", f"env:{KEYPASS_ENV}"]
    if options:
        command += options.split()

    env_vars = {PASS_ENV: str(password)}
    if key_password:
        env_vars[KEYPASS_ENV] = str(key_password)

    result = run_command(command, env_vars)
    return f"Keystore created at {keystore_path}\n{result}"

CA_DIR = "./root_cas"

def save_root_ca(cert):
    """Store an uploaded root CA cert in the local CA store."""
    cert_path = cert.name if cert else ""
    if not cert_path:
        return "Error: No certificate file provided."
    os.makedirs(CA_DIR, exist_ok=True)
    dest = os.path.join(CA_DIR, os.path.basename(cert_path))
    with open(cert_path, "rb") as src, open(dest, "wb") as dst:
        dst.write(src.read())
    return f"Root CA saved: {dest}"

def load_all_root_cas():
    """Rehash the CA store so openssl trusts every saved root CA, then list them."""
    if not os.path.isdir(CA_DIR):
        return "No CA store yet. Save a root CA first."
    result = run_command(["openssl", "rehash", CA_DIR])
    certs = os.listdir(CA_DIR)
    listing = "\n".join(f"  {c}" for c in sorted(certs))
    return f"Trusted root CAs ({len(certs)}):\n{listing}\n\n{result}"

def verify_cert_against_root_cas(cert):
    """Verify an uploaded cert against every root CA in the local store."""
    cert_path = cert.name if cert else ""
    if not cert_path:
        return "Error: No certificate file provided."
    if not os.path.isdir(CA_DIR):
        return "No CA store yet. Save a root CA first."
    command = ["openssl", "verify", "-CApath", CA_DIR, cert_path]
    result = run_command(command)
    return f"Verification result:\n{result}"


BUNDLE_OUT = "./nginx-bundle.crt"
PEM_OUT = "./nginx.pem"
FULLCHAIN_OUT = "./nginx-fullchain.crt"
NOPASS_OUT = "./nginx-nopass.key"

def detect_pkcs7_format(path):
    """Detect PKCS#7 container format: PEM if '-----BEGIN PKCS7-----' present, DER if first byte is 0x30, else 'unknown'."""
    try:
        with open(path, "rb") as f:
            content = f.read()
        if b"-----BEGIN PKCS7-----" in content:
            return "PEM"
        if content.startswith(b"\x30"):  # ASN.1 SEQUENCE tag typical of DER
            return "DER"
        return "unknown"
    except OSError as e:
        return f"error: {e}"

def key_is_encrypted(path):
    """True if file bytes contain 'ENCRYPTED PRIVATE KEY' (PKCS#8) or 'Proc-Type: 4,ENCRYPTED' (traditional PEM)."""
    try:
        with open(path, "rb") as f:
            content = f.read()
    except OSError:
        return False
    return b"ENCRYPTED PRIVATE KEY" in content or b"Proc-Type: 4,ENCRYPTED" in content

def p7b_to_bundle(p7b):
    """Step 1: extract the certificate chain from a PKCS#7 (.p7b) file into nginx-bundle.crt."""
    p7b_path = p7b.name if p7b else ""
    if not p7b_path:
        return "Error: upload a .p7b file first.", None
    fmt = detect_pkcs7_format(p7b_path)
    if fmt not in ("PEM", "DER"):
        return f"Error: cannot detect PKCS#7 format of {os.path.basename(p7b_path)} (detected: {fmt}).", None
    result = run_command(["openssl", "pkcs7", "-print_certs", "-inform", fmt,
                          "-in", p7b_path, "-out", BUNDLE_OUT])
    if "command failed with exit code" in result:
        return f"Error: Step 1 failed for {os.path.basename(p7b_path)}\n{result}", None
    return f"Step 1 done: {os.path.basename(p7b_path)} -> {BUNDLE_OUT} (input {fmt})\n{result}", BUNDLE_OUT

def crt_to_nginx_pem(crt):
    """Step 2: convert a DER certificate to PEM (nginx.pem); PEM input is copied as-is."""
    crt_path = crt.name if crt else ""
    if not crt_path:
        return "Error: upload a .crt file first.", None
    detected = detect_format(crt_path)
    if detected == "DER":
        result = run_command(["openssl", "x509", "-inform", "DER", "-in", crt_path, "-out", PEM_OUT])
        if "command failed with exit code" in result:
            return f"Error: Step 2 failed for {os.path.basename(crt_path)}\n{result}", None
        return f"Step 2 done: {os.path.basename(crt_path)} -> {PEM_OUT} (input DER)\n{result}", PEM_OUT
    if detected == "PEM":
        try:
            with open(crt_path, "rb") as src, open(PEM_OUT, "wb") as dst:
                dst.write(src.read())
        except OSError as e:
            return f"Error: Step 2 copy failed: {e}", None
        return f"Step 2 done: {os.path.basename(crt_path)} already PEM, copied to {PEM_OUT}", PEM_OUT
    return f"Error: Step 2 needs a DER or PEM certificate, detected: {detected}.", None

def build_fullchain():
    """Step 3: concatenate nginx.pem + nginx-bundle.crt into nginx-fullchain.crt."""
    for step, path in (("2", PEM_OUT), ("1", BUNDLE_OUT)):
        if not os.path.isfile(path):
            return f"Error: {path} missing — run step {step} first.", None
    try:
        with open(PEM_OUT, "rb") as f:
            leaf = f.read()
        with open(BUNDLE_OUT, "rb") as f:
            bundle = f.read()
    except OSError as e:
        return f"Error: Step 3 read failed: {e}", None
    data = leaf + bundle
    try:
        with open(FULLCHAIN_OUT, "wb") as f:
            f.write(data)
    except OSError as e:
        return f"Error: Step 3 write failed: {e}", None
    n = data.count(b"-----BEGIN CERTIFICATE-----")
    return f"Step 3 done: {FULLCHAIN_OUT} written ({len(data)} bytes, {n} certificates)", FULLCHAIN_OUT

def decrypt_key(key, key_password):
    """Step 4: rewrite a (possibly passphrase-protected) private key as unencrypted nginx-nopass.key."""
    key_path = key.name if key else ""
    if not key_path:
        return "Error: upload a private key file first.", None
    enc = key_is_encrypted(key_path)
    result = run_command(["openssl", "pkey", "-passin", f"env:{KEYPASS_ENV}",
                          "-in", key_path, "-out", NOPASS_OUT],
                         env_vars={KEYPASS_ENV: str(key_password or "")})
    if "command failed with exit code" in result:
        return f"Error: Step 4 failed for {os.path.basename(key_path)}\n{result}", None
    return (f"Step 4: key detected as {'encrypted' if enc else 'unencrypted'}\n"
            f"Step 4 done: {os.path.basename(key_path)} -> {NOPASS_OUT}\n{result}"), NOPASS_OUT

def run_nginx_pipeline(p7b, crt, key, key_password):
    """Steps 1,2 run when their input is present; step 3 only when BOTH p7b and crt
    ran; step 4 only when key present. Stops at first failing step, returns
    (log, BUNDLE_OUT-or-None, PEM_OUT-or-None, FULLCHAIN_OUT-or-None, NOPASS_OUT-or-None)."""
    logs = []
    bundle = pem = fullchain = nopass = None
    if not (p7b or crt or key):
        return "Error: upload at least one file (p7b, crt, or key) first.", None, None, None, None
    if p7b:
        log, bundle = p7b_to_bundle(p7b)
        logs.append(log)
        if bundle is None:
            return "\n\n".join(logs), None, None, None, None
    if crt:
        log, pem = crt_to_nginx_pem(crt)
        logs.append(log)
        if pem is None:
            return "\n\n".join(logs), bundle, None, None, None
    if p7b and crt:
        log, fullchain = build_fullchain()
        logs.append(log)
        if fullchain is None:
            return "\n\n".join(logs), bundle, pem, None, None
    if key:
        log, nopass = decrypt_key(key, key_password)
        logs.append(log)
        if nopass is None:
            return "\n\n".join(logs), bundle, pem, fullchain, None
    return "\n\n".join(logs), bundle, pem, fullchain, nopass

def nginx_status(p7b, crt, key):
    """Render the live status chips (one per upload slot) as an HTML string."""
    chips = []
    if p7b and getattr(p7b, "name", ""):
        fmt = detect_pkcs7_format(p7b.name)
        chips.append(f'<span class="chip {"ok" if fmt in ("PEM", "DER") else "warn"}">p7b · PKCS7 {fmt}</span>')
    else:
        chips.append('<span class="chip bad">p7b · missing</span>')
    if crt and getattr(crt, "name", ""):
        fmt = detect_format(crt.name)
        chips.append(f'<span class="chip {"ok" if fmt in ("PEM", "DER") else "warn"}">crt · {fmt}</span>')
    else:
        chips.append('<span class="chip bad">crt · missing</span>')
    if key and getattr(key, "name", ""):
        if key_is_encrypted(key.name):
            chips.append('<span class="chip ok">key · PEM encrypted — passphrase needed</span>')
        else:
            chips.append('<span class="chip ok">key · unencrypted</span>')
    else:
        chips.append('<span class="chip bad">key · missing</span>')
    return '<div style="margin:4px 0 8px">' + "".join(chips) + "</div>"
def create_dataframe(data):
    df = pd.DataFrame(data)  # Empty rows for user input
    return df
def create_dataframe_org(server_name,org):
    org=org.lower()
    data = {
        "Nr.": ["DNS.1", "DNS.2", "DNS.3", "DNS.4"],
        "DNS Alt Name": [f"{server_name}", f"{server_name}.{org}.com", "actual_server", f"actual_server.{org}.com"]
    }
    df = pd.DataFrame(data)  # Empty rows for user input
    return df

def update_keyfile(server_name):
    return f"{server_name}.key" if server_name else ""
def update_pass(server_name):
    return f"{server_name}" if server_name else ""
def update_cn(server_name,company):
    return f"{server_name}.{company.lower()}.com" if server_name else ""
def update_email(server_name,company):
    return f"admin_{server_name}@{company.lower()}.com" if server_name else ""
def _wipe_generated_files():
    """Delete certificate/keystore files this tool generated in the working dir.

    Uploaded files live in Gradio's temp dir (not the working directory), so user
    files are never touched — only the .cnf/.key/.csr/keystore/nginx outputs.
    """
    exts = {".cnf", ".csr", ".key", ".crt", ".pem", ".jks", ".pfx", ".p12", ".p7b", ".der", ".srl"}
    removed = []
    for entry in os.scandir("."):
        if entry.is_file() and os.path.splitext(entry.name)[1].lower() in exts:
            try:
                os.remove(entry.path)
                removed.append(entry.name)
            except OSError:
                pass
    return removed


def clear_session():
    """Delete every downloadable this session produced and reset all fields."""
    removed = _wipe_generated_files()
    if removed:
        gr.Info(f"Cleared session — deleted {len(removed)} file(s): " + ", ".join(sorted(removed)))
    else:
        gr.Info("Session reset — no downloadable files to delete.")
    # One value per component, in the exact order of CLEAR_OUTPUTS wired at the bottom.
    return (
        "",                          # csr_output
        "",                          # server_name
        2048,                        # default_bits
        "",                          # default_keyfile
        "req_distinguished_name",    # distinguished_name
        "no",                        # prompt
        "",                          # password
        "req_ext",                   # req_extensions
        "DE",                        # country
        "Baden-Wuerttemberg",        # state
        "Ulm",                       # locality
        "Company",                   # org
        "OSRB",                      # org_unit
        "",                          # cn
        "",                          # email
        "@alt_names",                # subjectAltName
        {"Nr.": ["DNS.1", "DNS.2", "DNS.3", "DNS.4"], "DNS Alt Name": ["", "", "", ""]},  # dataframe
        "./",                        # default_save_location
        None,                        # cnf_file_view
        None,                        # key_file_view
        None,                        # csr_file_view
        None,                        # f_p7b
        None,                        # f_crt
        None,                        # f_key
        "",                          # key_pass
        nginx_status(None, None, None),  # status_html
        "",                          # log_box
        None,                        # dl_bundle
        None,                        # dl_pem
        None,                        # dl_fullchain
        None,                        # dl_nopass
        None,                        # conv_cert
        "",                          # detected_format
        "PEM",                       # new_format
        "./",                        # new_place
        "",                          # convert_output
        None,                        # ks_cert
        None,                        # ks_key
        "",                          # ks_password
        "",                          # ks_key_password
        "Linux",                     # platform
        "./",                        # Keystore_save_place
        "",                          # keystore_output
        None,                        # ca_file
        "",                          # ca_output
        None,                        # verify_file
        "",                          # verify_output
    )


# --- palette (adaptive: each ramp is used by Gradio in both light and dark mode) ---
INDIGO = gr.themes.Color("#eef2ff", "#e0e7ff", "#c7d2fe", "#a5b4fc", "#818cf8", "#6366f1", "#4f46e5", "#4338ca", "#3730a3", "#312e81", "#1e1b4b")
TEAL = gr.themes.Color("#f0fdfa", "#ccfbf1", "#99f6e4", "#5eead4", "#2dd4bf", "#14b8a6", "#0d9488", "#0f766e", "#115e59", "#134e4a", "#042f2e")
SLATE = gr.themes.Color("#f8fafc", "#f1f5f9", "#e2e8f0", "#cbd5e1", "#94a3b8", "#64748b", "#475569", "#334155", "#1e293b", "#0f172a", "#020617")

THEME = gr.themes.Soft(
    primary_hue=INDIGO,
    secondary_hue=TEAL,
    neutral_hue=SLATE,
    font=["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Helvetica Neue", "Arial", "sans-serif"],
    font_mono=["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
).set(
    block_border_width="1px",
    block_radius="16px",
    block_shadow="0 1px 2px rgba(15,23,42,.05), 0 10px 28px -14px rgba(15,23,42,.18)",
    input_radius="10px",
    input_border_color_focus="rgba(79,70,229,.65)",
    input_shadow_focus="0 0 0 3px rgba(99,102,241,.16)",
    button_primary_background_fill="linear-gradient(135deg,#6366f1,#4338ca)",
    button_primary_background_fill_hover="linear-gradient(135deg,#4f46e5,#3730a3)",
    button_primary_border_color="transparent",
    button_secondary_background_fill_hover="rgba(99,102,241,.10)",
    button_large_radius="10px",
    button_medium_radius="10px",
    button_small_radius="10px",
    checkbox_background_color_selected="#4f46e5",
    checkbox_border_color_selected="#4f46e5",
)

CSS = """
.gradio-container { max-width: 1180px !important; }

/* focus ring */
.wrap:focus-within, textarea:focus, input:focus { box-shadow: 0 0 0 3px rgba(99,102,241,.16) !important; }
/* soft page depth that reads on light + dark */
.gradio-container::before {
  content: ""; position: fixed; inset: 0; z-index: -1; pointer-events: none;
  background:
    radial-gradient(1100px 520px at 100% -12%, rgba(99,102,241,.16), transparent 60%),
    radial-gradient(900px 480px at -12% 6%, rgba(20,186,166,.13), transparent 55%);
}

/* hero */
.hero {
  position: relative; overflow: hidden; padding: 26px 30px; margin-bottom: 16px;
  border-radius: 20px; color: #fff;
  background: linear-gradient(135deg, #4f46e5 0%, #6d28d9 55%, #0f766e 150%);
  box-shadow: 0 20px 44px -20px rgba(49,46,129,.65); border: 1px solid rgba(255,255,255,.14);
}
.hero::after { content: ""; position: absolute; inset: 0; pointer-events: none;
  background: radial-gradient(620px 200px at 12% -10%, rgba(255,255,255,.24), transparent 60%); }
.hero h1 { margin: 0; font-size: 1.85rem; font-weight: 800; letter-spacing: -.02em; color: #fff; position: relative; z-index: 1; }
.hero p { margin: 8px 0 0; color: #eef2ff; opacity: .92; font-size: .98rem; position: relative; z-index: 1; }
.hero .badges { margin-top: 14px; position: relative; z-index: 1; }
.hero .badge { display: inline-block; margin: 0 8px 0 0; padding: 4px 12px; border-radius: 999px;
  background: rgba(255,255,255,.16); border: 1px solid rgba(255,255,255,.28); color: #fff; font-size: .76rem; font-weight: 600; }

/* toolbar with the clear / new-session button */
.toolbar { align-items: center; margin-bottom: 4px; }
.toolbar-hint { color: var(--body-text-color-subdued, #94a3b8); font-size: .85rem; padding-top: 8px; }
.clear-btn { font-weight: 700 !important; border-radius: 12px !important; }

/* buttons: gradients read reliably across light/dark (theme gradient tokens are ignored by Gradio) */
.gradio-container button.primary { background-image: linear-gradient(135deg,#6366f1,#4338ca) !important; border-color: transparent !important; transition: background-image .18s ease, transform .05s ease; }
.gradio-container button.primary:hover { background-image: linear-gradient(135deg,#4f46e5,#3730a3) !important; }
.gradio-container button.primary:active { transform: translateY(1px); }
.gradio-container button.secondary { transition: background-color .15s ease; }
.gradio-container button.stop { background-image: linear-gradient(135deg,#fb7185,#e11d48) !important; border-color: transparent !important; }
.gradio-container button.stop:hover { background-image: linear-gradient(135deg,#f43f5e,#be123c) !important; }
.gradio-container button.stop:active { transform: translateY(1px); }

/* section headings */
.gradio-container h3 { display: flex; align-items: center; gap: 8px; margin: 2px 0 12px;
  font-size: 1.02rem; font-weight: 700; color: var(--body-text-color); }
.gradio-container h3::before { content: ""; width: 10px; height: 10px; border-radius: 3px; flex: 0 0 auto;
  background: linear-gradient(135deg,#6366f1,#14b8a6); box-shadow: 0 0 0 3px rgba(99,102,241,.14); }

/* download cards — remove the cramped inner scrollbar that pinned height to 50px */
.filecard { min-height: 108px !important; }
.filecard .file-preview-holder { height: auto !important; min-height: 62px; overflow: visible !important; }
.filecard table.file-preview { width: 100%; }
.filecard tr.file { border-radius: 10px; background: rgba(99,102,241,.05); }
.filecard .download-link { padding: 4px 10px !important; border-radius: 8px !important;
  background: rgba(99,102,241,.14); font-weight: 600; white-space: nowrap; }

/* chips (live nginx status) */
.chip { display: inline-block; padding: 3px 12px; margin-right: 6px; border-radius: 999px;
  font-size: .8rem; font-weight: 600; border: 1px solid transparent; }
.chip.ok   { background: rgba(16,185,129,.14);  color: #059669;  border-color: rgba(16,185,129,.32); }
.chip.warn { background: rgba(245,158,11,.14);  color: #b45309;  border-color: rgba(245,158,11,.32); }
.chip.bad  { background: rgba(239,68,68,.14);   color: #dc2626;  border-color: rgba(239,68,68,.32); }

/* dataframe */
.dataframe { font-size: .9rem; }
.dataframe th { background: linear-gradient(180deg, rgba(99,102,241,.12), rgba(99,102,241,.03)) !important; font-weight: 700; }

/* footer */
.appfoot { margin-top: 26px; padding: 14px; text-align: center; letter-spacing: .02em;
  color: var(--body-text-color-subdued, #94a3b8); font-size: .82rem; }
"""

HERO_HTML = (
    '<div class="hero"><h1>SSL Cert Toolkit</h1>'
    '<p>CSR generation · format conversion · keystores · root-CA trust — all via openssl</p>'
    '<div class="badges"><span class="badge">openssl powered</span>'
    '<span class="badge">runs locally</span>'
    '<span class="badge">nothing leaves this container</span></div></div>'
)

with gr.Blocks(title="SSL Cert Toolkit") as demo:
    gr.HTML(HERO_HTML)
    with gr.Row(elem_classes="toolbar"):
        gr.HTML('<div class="toolbar-hint">Generate files, download them, then clear everything to start a fresh certificate.</div>')
        clear_btn = gr.Button("🗑  New Session / Clear", variant="stop", elem_classes="clear-btn", scale=0, min_width=240)

    with gr.Tab("CSR Request"):
        with gr.Row():
            with gr.Column(elem_classes="card"):
                gr.HTML("<h3>Main Section</h3>")
                server_name = gr.Textbox(label="Server Name", info="single word without spaces")
                default_bits = gr.Number(label="Default bits",value=2048,interactive=True)
                default_keyfile = gr.Textbox(label="Default Keyfile", info="Private keyfile.usually server_name.key")
                distinguished_name = gr.Textbox(label="Distinguished Name",value="req_distinguished_name",interactive=False)
                prompt = gr.Textbox(label="Prompt",value='no',interactive=False)
                password = gr.Textbox(label="password",value='no',type="password",interactive=True,info="default will be same as server name.(use single word without spaces)")
                server_name.change(fn=update_pass, inputs=server_name, outputs=password)
                req_extensions = gr.Textbox(label="Req extensions",value="req_ext",interactive=False)
                server_name.change(fn=update_keyfile, inputs=server_name, outputs=default_keyfile)

            with gr.Column(elem_classes="card"):
                gr.HTML("<h3>[req_distinguished_name]</h3>")
                country = gr.Textbox(label="Country (C)",value="DE", info="single word without spaces")
                state = gr.Textbox(label="State (ST)",value="Baden-Wuerttemberg", info="single word without spaces")
                locality = gr.Textbox(label="Locality (L)",value="Ulm", info="single word without spaces")
                org = gr.Textbox(label="Organization (O)",value="Company")
                org_unit = gr.Textbox(label="Organizational Unit (OU)",value="OSRB", info="single word without spaces")
                cn = gr.Textbox(label="Common Name (CN)",value="", info="single word without spaces")
                server_name.change(fn=update_cn, inputs=[server_name,org], outputs=cn)
                org.change(fn=update_cn, inputs=[server_name,org], outputs=cn)
                email = gr.Textbox(label="Email Address",type='email',value="nightly@company.com")
                org.change(fn=update_email, inputs=[server_name,org], outputs=email)
        with gr.Row():
            with gr.Column(elem_classes="card"):
                gr.HTML("<h3>[req_ext]</h3>")
                subjectAltName = gr.Textbox(label="subjectAltName",value="@alt_names",interactive=False)
                data = {
                    "Nr.": ["DNS.1", "DNS.2", "DNS.3", "DNS.4"],
                    "DNS Alt Name": ["", "", "", ""]
                }
                dataframe = gr.Dataframe(
                    create_dataframe(data),
                    headers=["Nr.", "DNS Alt Name"], 
                    datatype=["str", "str"], 
                    interactive=True,
                    row_count=4,
                    column_count=2,
                )
                server_name.change(fn=create_dataframe_org, inputs=[server_name,org], outputs=dataframe)
                org.change(fn=create_dataframe_org, inputs=[server_name,org], outputs=dataframe)
            with gr.Column(elem_classes="card"):
                gr.HTML("<h3>Output location</h3>")
                default_save_location =gr.Textbox(label="Default save location",value="./",interactive=False)
                csr_output = gr.Textbox(label="CSR Output",lines=8)
        with gr.Row():
            with gr.Column():
                cnf_file_view = gr.File(label="downloadable cnf",interactive=False, height=110, elem_classes="filecard")
            with gr.Column():
                key_file_view = gr.File(label="downloadable key",interactive=False, height=110, elem_classes="filecard")
            with gr.Column():
                csr_file_view = gr.File(label="downloadable certificate",interactive=False, height=110, elem_classes="filecard")
        with gr.Row():
            with gr.Column():
                gr.Button("Create CSR", variant="primary").click(create_csr, [prompt,password,default_bits, default_keyfile,distinguished_name,
                                                   req_extensions,server_name, country, state, locality, \
                                                   org, org_unit, cn, email,subjectAltName,default_save_location,dataframe], [csr_output,cnf_file_view,key_file_view,csr_file_view])
            with gr.Column():
                gr.Button("Delete CSR in server", variant="stop").click(delete_csr, [default_save_location,server_name],[csr_output,cnf_file_view,key_file_view,csr_file_view])
            
    with gr.Tab("Nginx Converter"):
        gr.HTML('<p>Convert nginx-issued DER/PKCS#7 material into a fullchain + unencrypted key.</p>')
        with gr.Row():
            f_p7b = gr.File(label="nginx.p7b (PKCS#7)", file_count="single", height=110, interactive=True)
            f_crt = gr.File(label="nginx.crt (DER cert)", file_count="single", height=110, interactive=True)
            f_key = gr.File(label="nginx.key (private key)", file_count="single", height=110, interactive=True)
        key_pass = gr.Textbox(label="Key Passphrase", type="password", info="only if the key file is encrypted")
        status_html = gr.HTML(nginx_status(None, None, None))
        for f in (f_p7b, f_crt, f_key):
            f.change(fn=nginx_status, inputs=[f_p7b, f_crt, f_key], outputs=status_html)
        with gr.Row():
            btn_all = gr.Button("Convert All", variant="primary")
            btn_reset = gr.Button("Reset", variant="secondary")
        with gr.Row():
            b1 = gr.Button("1 · p7b → bundle.crt", variant="secondary")
            b2 = gr.Button("2 · crt → pem", variant="secondary")
            b3 = gr.Button("3 · build fullchain", variant="secondary")
            b4 = gr.Button("4 · key → nopass.key", variant="secondary")
        log_box = gr.Textbox(label="Pipeline Log", lines=10, interactive=False)
        with gr.Row():
            dl_bundle = gr.File(label="nginx-bundle.crt", height=110, elem_classes="filecard")
            dl_pem = gr.File(label="nginx.pem", height=110, elem_classes="filecard")
            dl_fullchain = gr.File(label="nginx-fullchain.crt", height=110, elem_classes="filecard")
            dl_nopass = gr.File(label="nginx-nopass.key", height=110, elem_classes="filecard")
        b1.click(p7b_to_bundle, [f_p7b], [log_box, dl_bundle])
        b2.click(crt_to_nginx_pem, [f_crt], [log_box, dl_pem])
        b3.click(build_fullchain, None, [log_box, dl_fullchain])
        b4.click(decrypt_key, [f_key, key_pass], [log_box, dl_nopass])
        btn_all.click(run_nginx_pipeline, [f_p7b, f_crt, f_key, key_pass],
                      [log_box, dl_bundle, dl_pem, dl_fullchain, dl_nopass])
        btn_reset.click(lambda: (None, None, None, None, "", "", None, None, None, None),
                        None, [f_p7b, f_crt, f_key, key_pass, log_box, status_html, dl_bundle, dl_pem, dl_fullchain, dl_nopass])
    with gr.Tab("Convert Certificate"):
        conv_cert = gr.File(label="Certificate File",file_count='single',interactive=True,height=120)
        with gr.Row():
            with gr.Column():
                detected_format = gr.Textbox(label="Detected Format",interactive=False)
            with gr.Column():
                new_format = gr.Dropdown(["PEM", "DER"], label="New Format", value="PEM")
        new_place=gr.Textbox(label="New Place",info="To store converted certificate",value="./",interactive=False)
        convert_output = gr.Textbox(label="Conversion Output")
        gr.Button("Convert", variant="primary").click(convert_certificate, [conv_cert, new_place, new_format], [convert_output, detected_format, new_format])
    
    with gr.Tab("Create New Keystore"):
        ks_cert = gr.File(label="Keystore Certificate",file_count='single',height=120,interactive=True)
        ks_key = gr.File(label="Certificate Key",file_count='single',height=120,interactive=True)
        ks_password = gr.Textbox(label="Keystore Password", type="password")
        ks_key_password = gr.Textbox(label="Key Password", type="password", info="passphrase of the uploaded key file, if any")
        platform = gr.Dropdown(["Linux", "Windows"], label="Platform")
        Keystore_save_place = gr.Textbox(label="Keystore save place",info="To store loaded keystore",value="./",interactive=False)
        keystore_output = gr.Textbox(label="Keystore Output")
        gr.Button("Create Keystore now", variant="primary").click(create_keystore, [ks_cert, ks_key, ks_password, platform,Keystore_save_place,ks_key_password], keystore_output)

    with gr.Tab("Root CA Integrator"):
        gr.HTML("<h2>Manage local root CA store</h2>")
        gr.HTML("Root CA certificates are stored in ./root_cas and trusted by openssl verify via -CApath.")
        ca_file = gr.File(label="Root CA Certificate",file_count='single',height=120,interactive=True)
        ca_output = gr.Textbox(label="Root CA Output",lines=8)
        with gr.Row():
            with gr.Column():
                gr.Button("Save Root CA", variant="primary").click(save_root_ca, [ca_file], ca_output)
            with gr.Column():
                gr.Button("load all ROOT CAs", variant="secondary").click(load_all_root_cas, None, ca_output)
        gr.HTML("<h2>Verify a certificate against the store</h2>")
        verify_file = gr.File(label="Certificate to verify",file_count='single',height=120,interactive=True)
        verify_output = gr.Textbox(label="Verification Output",lines=6)
        gr.Button("Verify against saved root CAs", variant="primary").click(verify_cert_against_root_cas, [verify_file], verify_output)

    gr.HTML('<div class="appfoot">runs openssl locally · nothing leaves this container</div>')

    CLEAR_OUTPUTS = [
        csr_output, server_name, default_bits, default_keyfile, distinguished_name,
        prompt, password, req_extensions, country, state, locality, org, org_unit,
        cn, email, subjectAltName, dataframe, default_save_location,
        cnf_file_view, key_file_view, csr_file_view,
        f_p7b, f_crt, f_key, key_pass, status_html, log_box,
        dl_bundle, dl_pem, dl_fullchain, dl_nopass,
        conv_cert, detected_format, new_format, new_place, convert_output,
        ks_cert, ks_key, ks_password, ks_key_password, platform, Keystore_save_place, keystore_output,
        ca_file, ca_output, verify_file, verify_output,
    ]

    clear_btn.click(
        fn=clear_session,
        inputs=None,
        outputs=CLEAR_OUTPUTS,
        js="""
() => {
  if (!window.confirm(
        "Start a new session?\\n\\n" +
        "This deletes ALL generated files (.cnf, .key, .csr, keystores, nginx outputs) " +
        "from the server and clears every field. This cannot be undone."
      )) { return false; }
}
""",
    )

if __name__ == "__main__":
    demo.launch(theme=THEME, css=CSS)
