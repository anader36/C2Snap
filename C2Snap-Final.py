#Importing the necessary libraries
import os
import time
import json
import tkinter as tk
from tkinter import ttk, simpledialog, scrolledtext, filedialog, messagebox
import pyautogui
import cv2
from PIL import Image, ImageTk
from geopy.geocoders import Bing
from geopy.exc import GeopyError
from datetime import datetime
import subprocess
import hashlib
import didkit
import base64
import cbor2
import tkinter.messagebox as msgbox
import tkinter.filedialog as filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.exceptions import InvalidSignature
from getpass import getpass 
import key_database
import asyncio

# This function converts any given file path into an absolute path.
def normalize_path(path):
    return os.path.abspath(path)

# The filename for the SQLite database where private keys and password hashes are stored.
DATABASE_FILENAME = "key_database.db"

# Initialize the master password cache to None
master_password_cache = None

# Ensure the "Screenshots" folder exists on the user's Desktop
desktop_path = os.path.expanduser("~/Desktop")
screenshots_folder = os.path.join(desktop_path, "Screenshots")
os.makedirs(screenshots_folder, exist_ok=True)

# Function to get the next ID for a file prefix
def get_next_id(files, prefix):
    ids = [int(f.split('_')[1]) for f in files if f.startswith(prefix) and f.endswith('.jpg')]
    return max(ids) + 1 if ids else 1

# Function to get the next screenshot ID
def get_next_screenshot_id():
    files = os.listdir(screenshots_folder)
    return get_next_id(files, 'screenshot')

# Function to get the next photo ID
def get_next_photo_id(folder):
    files = os.listdir(folder)
    return get_next_id(files, 'photo')

# Function to get the device manufacturer and model
def get_device_info():
    try:
        sysinfo_output = subprocess.check_output('systeminfo', shell=True).decode()
        manufacturer = next((line.split(":", 1)[1].strip() for line in sysinfo_output.split("\n") if "System Manufacturer" in line), "Unknown Manufacturer")
        model = next((line.split(":", 1)[1].strip() for line in sysinfo_output.split("\n") if "System Model" in line), "Unknown Model")
    except subprocess.CalledProcessError as e:
        gui_print(f"Error fetching system info: {e}")
        manufacturer, model = "Unknown Manufacturer", "Unknown Model"
    return {"manufacturer": manufacturer, "model": model}

# Function to get the geolocation of the user
def get_geolocation():
    api_key = os.getenv('BING_MAPS_API_KEY')  # Set this variable in your environment
    geolocator = Bing(api_key=api_key)
    try:
        location = geolocator.geocode("13 Ali Ibn Abi Taleb, Qesm 2nd New Cairo, Cairo, Egypt", exactly_one=True)
        if location:
            return {"latitude": location.latitude, "longitude": location.longitude, "address": location.address}
    except GeopyError as e:
        gui_print(f"Geopy error: {e}")
    return {"latitude": None, "longitude": None, "address": "Location not found"}

# Function to compute the SHA-256 hash of an image
def compute_image_hash(image_path):
#Compute SHA-256 hash of the image data.
    with open(image_path, 'rb') as f:
        image_data = f.read()
    return hashlib.sha256(image_data).hexdigest()

# Function to generate a decentralized identifier (DID) and store the private key in the database
def generate_did(image_path, master_password):
    did_keypair = didkit.generate_ed25519_key()
    jwk = json.loads(did_keypair)
    private_key = jwk['d']
    # Attempt to store the key immediately after generation
    successful_storage = key_database.store_private_key(DATABASE_FILENAME, private_key, master_password, image_path)
    if not successful_storage:
        gui_print("Failed to store the key.")
        return None
    else:
        gui_print("Key stored successfully.")
    return didkit.key_to_did("key", did_keypair)

# Function to extract the public key from a DID
def extract_public_key_from_did(did):
    async def get_jwk():
        jwk_json = await didkit.resolve_did(did, "{}")  # Ensure didkit is properly asynchronous
        return json.loads(jwk_json)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        jwk = loop.run_until_complete(get_jwk())
        verification_methods = jwk.get('verificationMethod', [])
        if verification_methods:
            public_key_jwk = verification_methods[0].get('publicKeyJwk', None)
            if public_key_jwk:
                public_key_b64 = public_key_jwk.get('x', None)
                if public_key_b64:
                    gui_print("Public Key (Base64): " + public_key_b64)
                    return public_key_b64
                else:
                    gui_print("Public key component not found in JWK.")
            else:
                gui_print("publicKeyJwk not found in verificationMethod.")
        else:
            gui_print("verificationMethod list is empty or not found.")
    except Exception as e:
        gui_print(f"Failed to extract public key from DID: {str(e)}")
    finally:
        loop.close()  # Properly close the loop to avoid resource leaks

    return None

# Function to correct the base64 padding of a string    
def correct_base64_padding(key):
    """Adds missing '=' paddings to the base64 encoded string if necessary."""
    padding_needed = len(key) % 4
    if padding_needed:
        key += '=' * (4 - padding_needed)
    return key

# Function to load and prepare the private key for signing
def load_and_prepare_private_key(image_path, master_password):
    try:
        private_key_encoded = key_database.load_private_key(image_path, master_password)
        if private_key_encoded is None:
            raise ValueError("No private key found for the provided image path.")
        private_key_encoded = correct_base64_padding(private_key_encoded)
        private_key_bytes = base64.urlsafe_b64decode(private_key_encoded)
        if len(private_key_bytes) != 32:
            raise ValueError("An Ed25519 private key must be exactly 32 bytes long.")
        return private_key_bytes
    except (TypeError, ValueError) as e:
        gui_print(f"Error loading or preparing private key: {e}")
        return None

# Function to sign a claim using the private key
def sign_c2pa_claim(claim_data, image_path, master_password):
    private_key_bytes = load_and_prepare_private_key(image_path, master_password)
    if private_key_bytes is None:
        return None
    try:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        signature = private_key.sign(claim_data)
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        gui_print(f"Failed to sign data: {e}")
        return None

# Function to create a JSON-LD metadata file for an image with COSE signature
def sign_cose(private_key, payload):
    try:
        # Directly sign the payload using the Ed25519 private key
        signature = private_key.sign(payload)
        return signature
    except Exception as e:
        gui_print(f"Failed to sign COSE: {e}")
        return None

# Function to create a JSON-LD metadata file
def create_jsonld_metadata(image_path, title, device_info, location_info, creation_timestamp, action_type, master_password):
    did = generate_did(image_path, master_password)
    if not did:
        gui_print("Failed to generate or store DID.")
        return
    public_key_b64 = extract_public_key_from_did(did)
    if not public_key_b64:
        gui_print("Failed to extract public key from DID.")
        return
    private_key_bytes = load_and_prepare_private_key(image_path, master_password)
    if not private_key_bytes:
        gui_print("Failed to load private key.")
        return
        # Extract public key from private key for DID generation
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    hash_value = compute_image_hash(image_path)
# Prepare the metadata
    # Prepare the actions and claims
    actions = [
        {
            "type": action_type,
            "timestamp": datetime.now().isoformat(),
            "actor": {
                "@type": "Person",
                "name": os.getlogin(),
                "email": "ah00355@tkh.edu.eg"
            },
            "tool": {
                "@type": "SoftwareApplication",
                "name": "C2Snap",
                "version": "1.0"
            },
            "description": "Creation of photo using C2Snap"
        }
    ]
    claims = [
        {
            "type": "CreatorAssertion",
            "name": os.getlogin(),
            "email": "ah00355@tkh.edu.eg"
        },
        {
            "type": "CreationTimestampAssertion",
            "timestamp": creation_timestamp
        },
        {
            "type": "DeviceAssertion",
            "manufacturer": device_info["manufacturer"],
            "model": device_info["model"]
        },
        {
            "type": "CopyrightOwnershipClaim",
            "subject": {"@id": image_path, "type": "ImageObject"},
            "copyrightHolder": {"@type": "Person", "name": os.getlogin()}
        },
        {
            "type": "DIDAssertion",
            "did": did
        },
        {
            "type": "LocationAssertion",
            "latitude": location_info.get("latitude"),
            "longitude": location_info.get("longitude"),
            "address": location_info.get("address")
        },
        {
            "type": "DIDPublicKey",
            "publicKey": public_key_b64
        }
    ]
    cbor_claims = cbor2.dumps(claims)  # Make sure this line is executed before the call to sign_c2pa_claim
    base64_cbor_claims = base64.b64encode(cbor_claims).decode('utf-8')
    hash_cbor = cbor2.dumps({
        "algorithm": "sha256",
        "value": hash_value 
    })
    base64_hash_cbor = base64.b64encode(hash_cbor).decode('utf-8') 
    # Sign the claim data
    signature = private_key.sign(cbor_claims)
    encoded_signature = base64.b64encode(signature).decode('utf-8')
    if not signature:
        gui_print("Failed to sign claims.")
        return
    manifest = create_c2pa_manifest(image_path, {'c2pa:signature': encoded_signature})
    metadata = {
        "c2pa:actions": actions,
        "claims": claims,
        "cbor_claims": base64_cbor_claims,
        "c2pa:signature": encoded_signature,
        "c2pa:signing_method": "Ed25519", 
        "c2pa:manifest": manifest,
        "@context": [
            "https://schema.org",
        ],
        "@type": "ImageObject",
        "name": os.path.basename(image_path),
        "author": {
            "@type": "Person",
            "name": os.getlogin(),
            "email": "ah00355@tkh.edu.eg"
        },
        "contentLocation": location_info,
        "dateCreated": creation_timestamp,
        "device": device_info,
        "license": "https://creativecommons.org/licenses/by/4.0/",
        "copyrightHolder": {
            "@type": "Organization",
            "name": "C2Snap"
        },
        "about": "Copyright © 2024 by C2Snap. All rights reserved. This content is licensed under the Creative Commons Attribution 4.0 International License.",
        "image": {
            "@type": "ImageObject",
            "url": image_path,
            "c2pa:contentAuthenticityHash": {
                "type": "ImageContentIntegrityAssertion",
                "contentAuthenticityHash": {
                    "algorithm": "sha256",
                    "value": hash_value,
                    "cbor_hash_value": base64_hash_cbor
                }
            }
        },
    }

    jsonld_path = os.path.splitext(image_path)[0] + '.jsonld'
    with open(jsonld_path, 'w') as f:
        json.dump(metadata, f, indent=4)
    gui_print(f"JSON-LD metadata saved to {jsonld_path}")

# Function to create a COSE manifest for a given image
def create_c2pa_manifest(image_path, metadata):
    # Load the signed claim (metadata['c2pa:signature'])
    signed_claim = base64.b64decode(metadata['c2pa:signature'])

    # Load your private key for COSE operations
    private_key_bytes = load_and_prepare_private_key(image_path, master_password_cache)  # Use cached master password
    if not private_key_bytes:
        gui_print("Failed to prepare private key.")
        return None
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

    # Construct the COSE Sign1 structure using cryptography primitives
    protected_header = {
        "alg": "EdDSA",
        "kid": base64.b64encode(hashlib.sha256(private_key_bytes).digest()).decode('utf-8')  # Key ID generated from a hash of the private key
    }
    protected_header_bytes = cbor2.dumps(protected_header)  # CBOR serialization of the header
    signature = private_key.sign(protected_header_bytes + signed_claim)

    # Create manifest - simplified representation suitable for JSON serialization
    manifest = {
        "protected": base64.urlsafe_b64encode(protected_header_bytes).decode('utf-8'),
        "unprotected": {},  # Assuming no unprotected headers
        "payload": base64.urlsafe_b64encode(signed_claim).decode('utf-8'),
        "signature": base64.urlsafe_b64encode(signature).decode('utf-8')
    }
    return manifest

# Function to extract the DID from a JSON-LD metadata file
def extract_did_from_metadata(metadata_path):
    try:
        with open(metadata_path, 'r') as file:
            metadata = json.load(file)
        # Find the claim with type 'DIDAssertion' and extract the DID
        for claim in metadata['claims']:
            if claim['type'] == 'DIDAssertion':
                return claim['did']
        gui_print("DID not found in the metadata.")
        return None
    except KeyError:
        gui_print("DID not found in the metadata.")
        return None
    except Exception as e:
        gui_print(f"Error reading metadata: {str(e)}")
        return None

# Function to verify the COSE signature in a metadata file    
def correct_base64_padding(base64_string):
    """Ensure the base64 string has the correct padding."""
    missing_padding = len(base64_string) % 4
    if missing_padding:
        base64_string += '=' * (4 - missing_padding)
    return base64_string

# Function to verify the COSE signature in a metadata file
def verify_cose_signature(metadata_path):
    """Verify the COSE signature in the metadata file."""
    try:
        with open(metadata_path, 'r') as file:
            metadata = json.load(file)
        
        # Retrieve the necessary components from the metadata
        if 'c2pa:manifest' in metadata:
            manifest = metadata['c2pa:manifest']
            signature_base64 = manifest.get('signature')
            payload_base64 = manifest.get('payload')
            protected_header_base64 = manifest.get('protected')
            
            if not signature_base64 or not payload_base64 or not protected_header_base64:
                messagebox.showerror("Signature Verification", "Missing signature components.")
                return False

            # Decode the base64 encoded values
            signature = base64.urlsafe_b64decode(signature_base64)
            payload = base64.urlsafe_b64decode(payload_base64)
            protected_header = base64.urlsafe_b64decode(protected_header_base64)

            # Retrieve and correct base64 encoded public key
            for claim in metadata.get('claims', []):
                if 'publicKey' in claim:
                    public_key_b64 = claim['publicKey']
                    break
            if not public_key_b64:
                messagebox.showerror("Signature Verification", "Public key not found in metadata.")
                return False

            public_key_b64 = correct_base64_padding(public_key_b64)
            public_key_bytes = base64.urlsafe_b64decode(public_key_b64)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

            # Verify the signature
            public_key.verify(signature, protected_header + payload)
            messagebox.showinfo("Signature Verification", "Signature is valid.")
            return True
        else:
            messagebox.showerror("Signature Verification", "No COSE manifest found.")
            return False
    except InvalidSignature:
        messagebox.showerror("Signature Verification", "Invalid signature.")
        return False
    except Exception as e:
        messagebox.showerror("Signature Verification", f"Error verifying signature: {str(e)}")
        return False

# Function to check and verify the COSE signature in a metadata file    
def check_signature():
    """Open a file dialog to select an image and check and verify COSE signature."""
    root = tk.Tk()
    root.withdraw()  # We don't want a full GUI, so keep the root window from appearing
    image_path = filedialog.askopenfilename(
        initialdir=screenshots_folder,
        title="Select an Image",
        filetypes=(("JPEG files", "*.jpg"), ("All files", "*.*"))
    )
    
    if image_path:
        metadata_path = os.path.splitext(image_path)[0] + '.jsonld'
        if os.path.exists(metadata_path):
            verify_cose_signature(metadata_path)
        else:
            messagebox.showerror("Signature Check", "No metadata file found for this image.")
    else:
        messagebox.showinfo("Signature Check", "No image was selected.")
    
    root.destroy()

# Function to print messages to the GUI console
def gui_print(message):
    if console_text is None or not tk.Toplevel.winfo_exists(console_window):
        open_console()
    console_text.insert(tk.END, message + "\n")
    console_text.see(tk.END)

# Function to open the console window
def open_console():
    global console_window, console_text
    if console_window is None or not tk.Toplevel.winfo_exists(console_window):
        console_window = tk.Toplevel(window)
        console_window.title("Output Console")
        console_window.geometry("600x400")
        console_text = scrolledtext.ScrolledText(console_window, state='normal')
        console_text.pack(fill=tk.BOTH, expand=True)

# Function to request the master password from the user
def request_master_password():
    global master_password_cache
    if master_password_cache is None:
        master_password_cache = simpledialog.askstring("Master Password", "Please enter the master password for the database:", show='*')
    return master_password_cache

# Function to capture an image from the camera
def capture_camera_image():
    master_password = request_master_password()
    if master_password is None:
        gui_print("User cancelled the operation.")
        return # User cancelled the operation
    camera_photos_folder = os.path.join(desktop_path, "Camera Photos")
    os.makedirs(camera_photos_folder, exist_ok=True)
    camera = cv2.VideoCapture(0)
    ret, frame = camera.read()
    camera.release()
    if ret:
        photo_id = get_next_photo_id(camera_photos_folder)
        image_path = normalize_path(os.path.join(camera_photos_folder, f"photo_{photo_id}_{time.strftime('%Y%m%d_%H%M%S')}.jpg"))
        cv2.imwrite(image_path, frame)
        create_jsonld_metadata(image_path, "Camera Photo - C2Snap", get_device_info(), get_geolocation(), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Creation of photo using C2Snap", master_password)
        gui_print(f"Photo and metadata saved at {image_path}")
    else:
        gui_print("Error: Could not access the camera.")

# Function to take a screenshot
def take_screenshot():
    master_password = request_master_password()
    if master_password is None:
        gui_print("User cancelled the operation.")
        return  # User cancelled the operation
    window.iconify()  # Minimize the window
    time.sleep(0.5)  # Wait a brief moment for the window to minimize
    screenshot_id = get_next_screenshot_id()
    image_path = normalize_path(os.path.join(screenshots_folder, f"screenshot_{screenshot_id}_{time.strftime('%Y%m%d_%H%M%S')}.jpg"))
    pyautogui.screenshot().save(image_path)
    create_jsonld_metadata(image_path, "Image Screenshot - C2Snap", get_device_info(), get_geolocation(), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Creation of photo using C2Snap", master_password)
    gui_print(f"Screenshot and metadata saved at {image_path}")
    window.deiconify()  # Restore the window

# Function to check if metadata exists for an image
def check_metadata():
    # Open file dialog to select an image
    image_path = filedialog.askopenfilename(
        initialdir=screenshots_folder,
        title="Select an Image",
        filetypes=(("JPEG files", "*.jpg"), ("All files", "*.*"))
    )
    
    if image_path:  # Proceed only if a file is selected
        # Generate the expected metadata file path
        metadata_file = os.path.splitext(image_path)[0] + '.jsonld'
        # Check if the metadata file exists
        if os.path.exists(metadata_file):
            msgbox.showinfo("Metadata Check", "Metadata is present for the selected image.")
        else:
            msgbox.showerror("Metadata Check", "Metadata is not present or may have been deleted.")
    else:
        msgbox.showinfo("Metadata Check", "No image was selected.")

# Initial Database Setup (Do this once when the user runs C2Snap for the first time)
if not os.path.exists(DATABASE_FILENAME):
    master_password = getpass("Create a master password for C2Snap: ")
    key_database.create_database(master_password)

# Initialize the main window
window = tk.Tk()
window.title("C2Snap - Content Authenticity Tool")
window.geometry("780x400")  # Adjust the size as needed

# Prepare a console window for output messages (not opened yet)
console_window = None
console_text = None

# Set a background color
window.configure(bg='#001f3d')

# Create a style
style = ttk.Style(window)
style.configure('TButton', font=('Arial', 16), borderwidth='4')
# Setting the background color and button text color
style.configure('TButton', background='#0099FF', foreground='#0099FF')
style.map('TButton', background=[('active', 'black')], foreground=[('active', '#FFD166')])

# Create a label with an image for the logo/title
logo_image = ImageTk.PhotoImage(Image.open("icons\logo_of_C2Snap-removebg-preview 1).png").resize((150, 150), Image.Resampling.LANCZOS))  # Replace with your logo path
logo_label = ttk.Label(window, image=logo_image)
logo_label.pack(pady=10)

# Create a colorful and stylish title below the logo
title_label = ttk.Label(window, text="C2Snap - Content Authenticity Tool", style="Title.TLabel")
title_label.pack()
style.configure("Title.TLabel", font=("Arial Bold", 18), foreground="#0099FF")  # Electric Blue title

# Create a label with a catchy sentence below the title
catchy_sentence_label = ttk.Label(window, text="Capture, Authenticate, Secure your Content!", style="Catchy.TLabel")
catchy_sentence_label.pack(pady=10)
style.configure("Catchy.TLabel", font=("Arial", 14), foreground="#595045")  # Neon Green catchy sentence

# Load and resize images for buttons
screenshot_img = Image.open('icons\screenshot2.png').resize((50, 50), Image.Resampling.LANCZOS)  # Resize to 50x50 pixels
screenshot_icon = ImageTk.PhotoImage(screenshot_img)
camera_img = Image.open('icons\camera.png').resize((50, 50), Image.Resampling.LANCZOS)  # Resize to 50x50 pixels
camera_icon = ImageTk.PhotoImage(camera_img)
check_img = Image.open('icons\search2.png').resize((50, 50), Image.Resampling.LANCZOS)  # Resize to 50x50 pixels
check_icon = ImageTk.PhotoImage(check_img)
checksign_img = Image.open('icons\contract.png').resize((50, 50), Image.Resampling.LANCZOS)  # Resize to 50x50 pixels
checksign_icon = ImageTk.PhotoImage(checksign_img)

# Adjust button placement and icon position
capture_button = ttk.Button(window, text="Capture", image=screenshot_icon, compound=tk.BOTTOM, command=take_screenshot)
capture_button.pack(side=tk.LEFT, expand=True, padx=20, pady=10)

take_picture_button = ttk.Button(window, text="Take a Picture", image=camera_icon, compound=tk.BOTTOM, command=capture_camera_image)
take_picture_button.pack(side=tk.RIGHT, expand=True, padx=20, pady=10)

check_button = ttk.Button(window, text="Check Metadata", image=check_icon, compound=tk.BOTTOM, command=check_metadata)
check_button.pack(side=tk.RIGHT, expand=True, padx=20, pady=10)

check_signature_cose_button = ttk.Button(window, text="Check Signature", image=checksign_icon, compound=tk.BOTTOM, command=check_signature)
check_signature_cose_button.pack(side=tk.RIGHT, expand=True, padx=20, pady=10)

# Main loop
window.mainloop()