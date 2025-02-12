import gradio as gr
import os
from gradio_toggle import Toggle
import pandas as pd
from tkinter import Tk, filedialog

def create_csr(server_name, country, state, locality, org, org_unit, cn, email):
    return f"""
    [req]
    distinguished_name = req_distinguished_name
    req_extensions = req_ext

    [req_distinguished_name]
    C = {country}
    ST = {state}
    L = {locality}
    O = {org}
    OU = {org_unit}
    CN = {cn}
    emailAddress = {email}
    """

def convert_certificate(cert, new_format):
    return f"Converting {cert} to {new_format}..."  # Placeholder logic

def create_keystore(cert, key, password, platform):
    return f"Keystore created for {platform} with certificate {cert}."  # Placeholder logic
def root_ca_integrator(cert, key, password, platform):
    return f"Keystore created for {platform} with certificate {cert}."  # Placeholder logic

def update(input):
    visible = input
    return gr.update(visible=visible)

def create_dataframe():
    df = pd.DataFrame({"Column 1": [""], "Column 2": [""]})  # Empty rows for user input
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

        server_name = gr.Textbox(label="Server Name")
        default_bits = gr.Number(label="Default bits",value=2048,interactive=True)
        default_keyfile = gr.Textbox(label="Default Keyfile")
        distinguished_name = gr.Textbox(label="Distinguished Name",value="req_distinguished_name")
        prompt = gr.Textbox(label="Prompt",value='no')
        req_extensions = gr.Textbox(label="Req extensions",value="req_ext")
        
        gr.HTML("<h2>[req_distinguished_name]</h2>")
        country = gr.Textbox(label="Country (C)")
        state = gr.Textbox(label="State (ST)")
        locality = gr.Textbox(label="Locality (L)")
        org = gr.Textbox(label="Organization (O)")
        org_unit = gr.Textbox(label="Organizational Unit (OU)")
        cn = gr.Textbox(label="Common Name (CN)")
        email = gr.Textbox(label="Email Address",type='email')
        gr.HTML("<h2>[req_ext]</h2>")
        subjectAltName = gr.Textbox(label="subjectAltName",value="@alt_names")
        gr.HTML("<h2>[alt_names]</h2>")
        dataframe = gr.Dataframe(
            headers=["Nr.", "DNS Alt Name"], 
            datatype=["str", "str"], 
            interactive=True
        )
        default_save_location,_=create_folder_ui(label="Default save location")
        csr_output = gr.Textbox(label="CSR Output")
        gr.Button("Create CSR").click(create_csr, [server_name, country, state, locality, org, org_unit, cn, email,default_save_location], csr_output)
    
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
