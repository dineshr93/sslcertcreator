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
with gr.Blocks() as demo:
    gr.HTML("<h1>SSL Certificate creator</h1>")
    with gr.Tab("CSR Request"):
        # with gr.Row():
        #     with gr.Column():
        #         read_config = Toggle(
        #             label="Read config from file?",
        #             value=False,
        #             info="Read config from file?",
        #             interactive=True,
        #         )
        #     with gr.Column():
        #         cnf_path = gr.File(
        #             label="CNF Path", 
        #             visible=False,
        #             file_count='single',
        #             interactive=True,
        #             height=120
        #             )
                #   read_config.change(fn=update, inputs=read_config, outputs=[cnf_path])S
        with gr.Row():
            with gr.Column():
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

            with gr.Column():
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
            with gr.Column():
                gr.HTML("<h3>[req_ext]</h3>")
                subjectAltName = gr.Textbox(label="subjectAltName",value="@alt_names",interactive=False)
                # gr.HTML("<h3>[alt_names]</h3>")
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
            with gr.Column():
                gr.HTML("<h3>Output location</h3>")
                # default_save_location,_=create_folder_ui(label="Default save location")
                default_save_location =gr.Textbox(label="Default save location",value="./",interactive=False)
                # gr.HTML("<h3>Output log</h3>")
                csr_output = gr.Textbox(label="CSR Output",lines=8)
        # file_output = gr.File(label="downloadable Files",interactive=True,height=120)
        with gr.Row():
            with gr.Column():
                cnf_file_view = gr.File(label="downloadable cnf",interactive=False, height=50)
            with gr.Column():
                key_file_view = gr.File(label="downloadable key",interactive=False, height=50)
            with gr.Column():
                csr_file_view = gr.File(label="downloadable certificate",interactive=False, height=50)
        with gr.Row():
            with gr.Column():
                gr.Button("Create CSR").click(create_csr, [prompt,password,default_bits, default_keyfile,distinguished_name,
                                                   req_extensions,server_name, country, state, locality, \
                                                   org, org_unit, cn, email,subjectAltName,default_save_location,dataframe], [csr_output,cnf_file_view,key_file_view,csr_file_view])
            with gr.Column():
                gr.Button("Delete CSR in server").click(delete_csr, [default_save_location,server_name],[csr_output,cnf_file_view,key_file_view,csr_file_view])
            
        
        
        
        
    
    with gr.Tab("Convert Certificate"):
        cert = gr.File(label="Certificate File",file_count='single',interactive=True,height=120)
        with gr.Row():
            with gr.Column():
                detected_format = gr.Textbox(label="Detected Format",interactive=False)
            with gr.Column():
                new_format = gr.Dropdown(["PEM", "DER"], label="New Format", value="PEM")
        new_place=gr.Textbox(label="New Place",info="To store converted certificate",value="./",interactive=False)
        convert_output = gr.Textbox(label="Conversion Output")
        gr.Button("Convert").click(convert_certificate, [cert, new_place, new_format], [convert_output, detected_format, new_format])
    
    with gr.Tab("Create New Keystore"):
        cert = gr.File(label="Keystore Certificate",file_count='single',height=120,interactive=True)
        key = gr.File(label="Certificate Key",file_count='single',height=120,interactive=True)
        password = gr.Textbox(label="Keystore Password", type="password")
        key_password = gr.Textbox(label="Key Password", type="password", info="passphrase of the uploaded key file, if any")
        platform = gr.Dropdown(["Linux", "Windows"], label="Platform")
        Keystore_save_place = gr.Textbox(label="Keystore save place",info="To store loaded keystore",value="./",interactive=False)
        keystore_output = gr.Textbox(label="Keystore Output")
        gr.Button("Create Keystore now").click(create_keystore, [cert, key, password, platform,Keystore_save_place,key_password], keystore_output)

    with gr.Tab("Root CA Integrator"):
        gr.HTML("<h2>Manage local root CA store</h2>")
        gr.HTML("Root CA certificates are stored in ./root_cas and trusted by openssl verify via -CApath.")
        ca_file = gr.File(label="Root CA Certificate",file_count='single',height=120,interactive=True)
        ca_output = gr.Textbox(label="Root CA Output",lines=8)
        with gr.Row():
            with gr.Column():
                gr.Button("Save Root CA").click(save_root_ca, [ca_file], ca_output)
            with gr.Column():
                gr.Button("load all ROOT CAs").click(load_all_root_cas, None, ca_output)
            with gr.Column():
                gr.Button("Verify certificate").click(verify_cert_against_root_cas, [ca_file], ca_output)
        gr.HTML("<h2>Verify a certificate against the store</h2>")
        verify_file = gr.File(label="Certificate to verify",file_count='single',height=120,interactive=True)
        verify_output = gr.Textbox(label="Verification Output",lines=6)
        gr.Button("Verify against saved root CAs").click(verify_cert_against_root_cas, [verify_file], verify_output)


demo.launch()
