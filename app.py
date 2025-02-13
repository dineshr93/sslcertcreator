import gradio as gr
import os
import pandas as pd
# from tkinter import Tk, filedialog

import subprocess

def run_command(cmd: str) :
    """Executes a Bash command and returns the output log."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip() if result.stdout else result.stderr.strip()

def delete_csr(default_save_location,server_name):

    cnf_file=os.path.join(default_save_location,f"{server_name}.cnf")
    key_file=os.path.join(default_save_location,f"{server_name}.key")
    csr_file=os.path.join(default_save_location,f"{server_name}.csr")
    cmd =""
    cmd = cmd + f"\n===deleted .cnf file========\n" +run_command(f"rm -rf {cnf_file}")
    cmd = cmd + f"\n===deleted .key file========\n" +run_command(f"rm -rf {key_file}")
    cmd = cmd + f"\n===deleted .csr file========\n" + run_command(f"rm -rf {csr_file}")
    cnf_file = gr.File(label="downloadable cnf",interactive=False)
    key_file = gr.File(label="downloadable key",interactive=False)
    csr_file = gr.File(label="downloadable certificate",interactive=False)
    return cmd,None,None,None

def create_csr(prompt,password,default_bits, default_keyfile,distinguished_name,
                req_extensions,server_name, country, state, locality,
                org, org_unit, cn, email,subjectAltName,default_save_location,dataframe):

    # output = run_command("ls -l")
    dns_alt_names = dataframe["DNS Alt Name"].tolist()
    DNS=""
    for i,name in enumerate(dns_alt_names,start=1):
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

    command = f"openssl req -new -config {cnf_file} -keyout {key_file} -out {csr_file} -passout pass:{password} -verbose"
    

    return run_command(command) + f"your passphrase is set as {password}",cnf_file,key_file,csr_file

def convert_certificate(cert, new_place):
    cert_path = cert.name if cert else ""
    if not cert_path:
        return "Error: No certificate file provided."
    
    new_cert_path = os.path.join(new_place, "converted_cert.pem")
    command = f"openssl x509 -in {cert} -out {new_cert_path} -outform PEM"
    
    result = run_command(command)
    return f"Conversion completed: {new_cert_path}\n{result}"

def create_keystore(cert, key, password, platform, keystore_place):
    cert_path = cert.name if cert else ""
    key_path = key.name if key else ""
    keystore_path = os.path.join(keystore_place, "keystore.jks")
    
    if not cert_path or not key_path:
        return "Error: Certificate or Key file missing."
    
    command = (
        f"openssl pkcs12 -export -in {cert_path} -inkey {key_path} "
        f"-out {keystore_path} -password pass:{password}"
    )
    
    result = run_command(command)
    return f"Keystore created at {keystore_path}\n{result}"

def root_ca_integrator(cert, key, password, platform):
    cert_path = cert.name if cert else ""
    key_path = key.name if key else ""
    
    if not cert_path or not key_path:
        return "Error: Certificate or Key file missing."
    
    command = f"openssl verify -CAfile {cert_path} {key_path}"
    result = run_command(command)
    
    return f"Root CA integration result:\n{result}"

def update(input):
    visible = input
    return gr.update(visible=visible)

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
                    col_count=2,
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
        new_place=gr.Textbox(label="New Place",info="To store converted certificate",value="./",interactive=False)
        with gr.Row():
            with gr.Column():
                detected_format = gr.Textbox(label="Detected Format",interactive=False)
            with gr.Column():
                new_format = gr.Textbox(label="New Format",interactive=False)
        convert_output = gr.Textbox(label="Conversion Output")
        gr.Button("Convert").click(convert_certificate, [cert, new_place], convert_output)
    
    with gr.Tab("Create New Keystore"):
        cert = gr.File(label="Keystore Certificate",file_count='single',height=120,interactive=True)
        key = gr.File(label="Certificate Key",file_count='single',height=120,interactive=True)
        password = gr.Textbox(label="Keystore Password", type="password")
        platform = gr.Dropdown(["Linux", "Windows"], label="Platform")
        Keystore_save_place = gr.Textbox(label="Keystore save place",info="To store loaded keystore",value="./",interactive=False)
        # Keystore_save_place = gr.Textbox(label="Keystore save place")

        keystore_output = gr.Textbox(label="Keystore Output")
        gr.Button("Create Keystore now").click(create_keystore, [cert, key, password, platform,Keystore_save_place], keystore_output)

    with gr.Tab("Root CA Integrator"):
        keystore = gr.File(label="Keystore",file_count='single',height=120,interactive=True)
        root_ca_url = gr.Textbox(label="Root CA URL")
        keystore_password = gr.Textbox(label="Keystore Password", type="password")
        with gr.Row():
            with gr.Column():
                gr.Button("Save Root CA URL as default").click(root_ca_integrator, [cert, key, password, platform], keystore_output)
                
            with gr.Column():
                gr.Button("load all ROOT CAs").click(root_ca_integrator, [cert, key, password, platform], keystore_output)
        gr.HTML("<h2>Root CA certs</h2>")
        dataframe = gr.Dataframe(
            headers=["Choose", "Certificate","Add Additional Certificates"], 
            datatype=["str", "str"], 
            interactive=True
        )
            
        
        keystore_output = gr.Textbox(label="Keystore Output")
        gr.Button("Add Certificates to Keystore").click(root_ca_integrator, [cert, key, password, platform], keystore_output)


demo.launch()
