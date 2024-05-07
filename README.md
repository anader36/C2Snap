![Screenshot 2024-04-04 120328](https://github.com/anader36/C2Snap/assets/93553393/75da921e-27dc-4e9c-af16-9c848e54fa41)



C2Snap - Image Authenticity and Integrity Tool - Project By: Ahmed Nader


# Overview
## Understanding C2PA:
The Coalition for Content Provenance and Authenticity (C2PA) is an initiative aimed at combating the challenges of misinformation and content tampering in digital media. C2PA develops standards to provide verifiable data about the origin and history of digital content, allowing creators and consumers to ascertain the authenticity of the media. By leveraging C2PA standards, tools can embed detailed metadata and cryptographic assurances directly into digital content, enhancing its security and trustworthiness.

## Problem Statement:
In the era of digital media, the manipulation of images can have far-reaching consequences, spreading misinformation and eroding trust. Whether it's altering photographs in news articles or modifying creator-owned content, the ease with which digital images can be altered poses a significant challenge to maintaining their authenticity and credibility.

## Proposed Solution with C2Snap:
C2Snap is developed as a graduation project with the aim of providing a robust solution to the problem of ensuring the authenticity and integrity of digital images. This tool integrates seamlessly with C2PA standards to embed cryptographic signatures and detailed metadata into images. These enhancements serve as tamper-evident seals, enabling both creators and consumers to verify the origin and integrity of the content at any point after its creation.

## C2PA Manifest Structure:
The image above illustrates the structure of a C2PA (Coalition for Content Provenance and Authenticity) manifest, which is integral to ensuring the authenticity and integrity of digital media. Here's a detailed breakdown of each component within the manifest structure:

1. Manifest Store: This is the top-level container that encapsulates all other components related to the digital content's provenance.
2. Claim Signature:
  - COSE Digital Signature: This is a digital signature format based on the CBOR Object Signing and Encryption (COSE) specification. It ensures the integrity and authenticity of the claim by digitally signing the entire content.
3. Claim:
  - CBOR structure: This part of the manifest contains the actual data claims about the media, encoded in Concise Binary Object Representation (CBOR). It references both the assertions made about the media and the digital signature that verifies these claims.
4. Assertion Store:
  - stds.exif: This JSON-LD (JavaScript Object Notation for Linked Data) structure contains metadata derived from the EXIF data of the image, such as details about the camera used and the geographic location where the photo was taken, providing contextual      information about the creation of the media.
  - c2pa.thumbnail.claim.jpg: This is a binary representation of the image data, often used as a thumbnail for quick reference.
  - c2pa.hash.data: This CBOR structure includes cryptographic hashes that bind directly to the content, ensuring that any alteration of the media can be detected. This binding serves as a proof of the media's original state at the time of creation.
    
This structure allows for a comprehensive, secure method to manage and verify the origins and authenticity of digital content, making it harder to misrepresent or tamper with media files. By utilizing such a manifest, creators and consumers can trust the veracity of the digital content and trace its origins effectively.

## Advantages of Using C2Snap:
- Enhanced Trust and Credibility: By ensuring that the image content is authentic and unaltered, C2Snap helps maintain and enhance the credibility of digital media.
- Protection Against Misinformation: With verified content, the spread of misinformation through doctored images can be significantly reduced.
- Empowerment of Content Creators: Creators can protect their intellectual property and ensure their audience receives content as intended, unmodified and authentic

# Key Features
- Image Capture: Capture images directly from your webcam or take screenshots with ease.
- Metadata Generation: Automatically generate detailed metadata for each image, including:
  - Device information (manufacturer, model)
  - Location data (if available)
  - Timestamps
- Cryptographic Signing: Embed Ed25519 digital signatures into your images to ensure their integrity and establish non-repudiation.
- Decentralized Identifiers (DIDs): Securely associate images with DIDs for robust and verifiable ownership claims.
- COSE Signature Verification: Implement COSE (CBOR Object Signing and Encryption) for flexible and efficient signature verification.
- User-Friendly GUI: Navigate the intuitive graphical user interface to effortlessly capture, sign, and verify images.

# Installation
## Prerequisites:

- Python 3.x (https://www.python.org/downloads/)
- Required libraries listed in the requirements.txt file

## Installation Steps:

1. Clone this repository:
```bash
  git clone https://github.com/anader36/C2Snap.git
```
2. Navigate to the project directory:
```bash
  cd C2Snap
```
3. Install dependencies:
```bash
  pip install -r requirements.txt
```

# Usage
1. Run the main Python script:
```bash
  python C2Snap-Final.py
```
2. The graphical user interface will launch. Follow the on-screen instructions and utilize the provided buttons for different functionalities:
- Capture: Take a new photo using your webcam.
- Take a Picture: Capture a screenshot of your desktop.
- Check Metadata: Verify if an image has associated metadata.
- Check Signature: Verify the digital signature (COSE) embedded within an image.

# How it Works
1. Image Capture: The tool can either take screenshots or capture images directly from your webcam.
2. Metadata Generation: When an image is captured, C2Snap collects relevant data such as timestamps, device information, and geolocation (if permitted by the user).
3. DID Generation: A unique Decentralized Identifier (DID) is generated for the image.
4. Cryptographic Signing:
  - The image data and its metadata are used to create a cryptographic hash.
  - Your private key (securely stored in an encrypted database) is used to sign the hash using Ed25519.
  - COSE is used to encapsulate the signature, providing standardized formatting.
5. Embedding: The metadata, DID, and the signature are embedded within the image file in a structured JSON-LD format.

# Project Structure
- C2Snap-Final.py: The main Python script containing core functionality.
- key_database.py: Module responsible for secure private key storage and retrieval.
- requirements.txt: Lists all necessary Python dependencies.
- icons/: Contains image icons used in the interface.

# License

This project is licensed under the MIT License.

# Contribution
I welcome contributions to improve and expand C2Snap! Feel free to open issues, submit pull requests, or suggest new features.

# Contact
If you have any questions or feedback, feel free to reach out to me at: ahmednader040@gmail.com

Thank you for exploring C2Snap!
