import gradio as gr
import os
from gradio_toggle import Toggle
import pandas as pd
from tkinter import Tk, filedialog

import subprocess

def run_command(cmd: str) -> str:
    """Executes a Bash command and returns the output log."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip() if result.stdout else result.stderr.strip()

def create_csr(cnf_path,prompt,password,default_bits, default_keyfile,distinguished_name,
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
    

    return run_command(command) + f"your passphrase is set as {password}"

def convert_certificate(cert, new_format):
    return f"Converting {cert} to {new_format}..."  # Placeholder logic

def create_keystore(cert, key, password, platform):
    return f"Keystore created for {platform} with certificate {cert}."  # Placeholder logic
def root_ca_integrator(cert, key, password, platform):
    return f"Keystore created for {platform} with certificate {cert}."  # Placeholder logic

def update(input):
    visible = input
    return gr.update(visible=visible)

def create_dataframe(data):
    df = pd.DataFrame(data)  # Empty rows for user input
    return df
def create_dataframe_org(server_name,org):
    data = {
        "Nr.": ["DNS.1", "DNS.2", "DNS.3", "DNS.4"],
        "DNS Alt Name": [f"{server_name}", f"{server_name}.{org}.com", "actual_server", f"actual_server.{org}.com"]
    }
    df = pd.DataFrame(data)  # Empty rows for user input
    return df

def get_folder_path(folder_path: str = "") -> str:
    """
    Opens a folder dialog to select a folder, allowing the user to navigate and choose a folder.
    If no folder is selected, returns the initially provided folder path or an empty string if not provided.
    This function is conditioned to skip the folder dialog on macOS or if specific environment variables are present,
    indicating a possible automated environment where a dialog cannot be displayed.

    Parameters:
    - folder_path (str): The initial folder path or an empty string by default. Used as the fallback if no folder is selected.

    Returns:
    - str: The path of the folder selected by the user, or the initial `folder_path` if no selection is made.

    Raises:
    - TypeError: If `folder_path` is not a string.
    - EnvironmentError: If there's an issue accessing environment variables.
    - RuntimeError: If there's an issue initializing the folder dialog.

    Note:
    - The function checks the `ENV_EXCLUSION` list against environment variables to determine if the folder dialog should be skipped, aiming to prevent its appearance during automated operations.
    - The dialog will also be skipped on macOS (`sys.platform != "darwin"`) as a specific behavior adjustment.
    """
    # Validate parameter type
    if not isinstance(folder_path, str):
        raise TypeError("folder_path must be a string")

    try:
        root = Tk()
        root.withdraw()
        root.wm_attributes("-topmost", 1)
        selected_folder = filedialog.askdirectory(initialdir=folder_path or ".")
        root.destroy()
        return selected_folder or folder_path
    except Exception as e:
        raise RuntimeError(f"Error initializing folder dialog: {e}") from e
def create_folder_ui(path="./",label="Directory",info="choose directory"):
    with gr.Row():
        text_box = gr.Textbox(
            label=label,
            info=info,
            lines=1,
            value=path,
        )
        button = gr.Button(value="\U0001f5c0", inputs=text_box, min_width=24)

        button.click(
            lambda: get_folder_path(text_box.value),
            outputs=[text_box],
        )

    return text_box, button
def update_keyfile(server_name):
    return f"{server_name}.key" if server_name else ""
def update_pass(server_name):
    return f"{server_name}" if server_name else ""
def update_cn(server_name,company):
    return f"{server_name}.{company}.com" if server_name else ""
def update_email(server_name,company):
    return f"admin_{server_name}@{company}.com" if server_name else ""
with gr.Blocks() as demo:
    gr.HTML("<h1>SSL Certificate creator</h1>")
    with gr.Tab("CSR Request"):
        with gr.Row():
            with gr.Column():
                read_config = Toggle(
                    label="Read config from file?",
                    value=False,
                    info="Read config from file?",
                    interactive=True,
                )
            with gr.Column():
                cnf_path = gr.File(
                    label="CNF Path", 
                    visible=False,
                    file_count='single',
                    interactive=True,
                    height=120
                    )
                
                read_config.change(fn=update, inputs=read_config, outputs=[cnf_path])

        server_name = gr.Textbox(label="Server Name", info="single word without spaces")
        default_bits = gr.Number(label="Default bits",value=2048,interactive=True)
        default_keyfile = gr.Textbox(label="Default Keyfile", info="Private keyfile.usually server_name.key")
        distinguished_name = gr.Textbox(label="Distinguished Name",value="req_distinguished_name",interactive=False)
        prompt = gr.Textbox(label="Prompt",value='no',interactive=False)
        password = gr.Textbox(label="password",value='no',type="password",interactive=True,info="default will be same as server name.(use single word without spaces)")
        server_name.change(fn=update_pass, inputs=server_name, outputs=password)
        req_extensions = gr.Textbox(label="Req extensions",value="req_ext",interactive=False)
        server_name.change(fn=update_keyfile, inputs=server_name, outputs=default_keyfile)
        
        gr.HTML("<h2>[req_distinguished_name]</h2>")
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
        gr.HTML("<h2>[req_ext]</h2>")
        subjectAltName = gr.Textbox(label="subjectAltName",value="@alt_names",interactive=False)
        gr.HTML("<h2>[alt_names]</h2>")

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
        default_save_location,_=create_folder_ui(label="Default save location")
        csr_output = gr.Textbox(label="CSR Output")
        gr.Button("Create CSR").click(create_csr, [cnf_path,prompt,password,default_bits, default_keyfile,distinguished_name,
                                                   req_extensions,server_name, country, state, locality, \
                                                   org, org_unit, cn, email,subjectAltName,default_save_location,dataframe], csr_output)
    
    with gr.Tab("Convert Certificate"):
        cert = gr.File(label="Certificate File",interactive=True,height=120)
        new_place,_=create_folder_ui(label="New Place",info="To store converted certificate")
        with gr.Row():
            with gr.Column():
                detected_format = gr.Textbox(label="Detected Format",interactive=False)
            with gr.Column():
                new_format = gr.Textbox(label="New Format",interactive=False)
        convert_output = gr.Textbox(label="Conversion Output")
        gr.Button("Convert").click(convert_certificate, [cert, new_place], convert_output)
    
    with gr.Tab("Create New Keystore"):
        cert = gr.File(label="Keystore Certificate",height=120,interactive=True)
        key = gr.File(label="Certificate Key",height=120,interactive=True)
        password = gr.Textbox(label="Keystore Password", type="password")
        platform = gr.Dropdown(["Linux", "Windows"], label="Platform")
        Keystore_save_place,_ = create_folder_ui(label="Keystore save place",info="To store loaded keystore")
        # Keystore_save_place = gr.Textbox(label="Keystore save place")

        keystore_output = gr.Textbox(label="Keystore Output")
        gr.Button("Create Keystore now").click(create_keystore, [cert, key, password, platform,Keystore_save_place], keystore_output)

    with gr.Tab("Root CA Integrator"):
        keystore = gr.File(label="Keystore",height=120,interactive=True)
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
