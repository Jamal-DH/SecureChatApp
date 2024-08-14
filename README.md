# Secure Chat Application

This project is a Secure Chat Application developed in Python and Java. The application ensures secure communication using encryption and provides a robust setup process for running on different systems.

## Project Structure

The project directory contains the following structure:

├───.venv
│   ├───Include
│   ├───Lib
│   │   └───site-packages
│   │       ├───cffi
│   │       │   └───__pycache__
│   │       ├───cffi-1.16.0.dist-info
│   │       ├───cryptography
│   │       │   ├───hazmat
│   │       │   │   ├───backends
│   │       │   │   │   ├───openssl
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───bindings
│   │       │   │   │   ├───openssl
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───_rust
│   │       │   │   │   │   └───openssl
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───decrepit
│   │       │   │   │   ├───ciphers
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───primitives
│   │       │   │   │   ├───asymmetric
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───ciphers
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───kdf
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───serialization
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───twofactor
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   └───__pycache__
│   │       │   ├───x509
│   │       │   │   └───__pycache__
│   │       │   └───__pycache__
│   │       ├───cryptography-43.0.0.dist-info
│   │       │   └───license_files
│   │       ├───pip
│   │       │   ├───_internal
│   │       │   │   ├───cli
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───commands
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───distributions
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───index
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───locations
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───metadata
│   │       │   │   │   ├───importlib
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───models
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───network
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───operations
│   │       │   │   │   ├───build
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───install
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───req
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───resolution
│   │       │   │   │   ├───legacy
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───resolvelib
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───utils
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───vcs
│   │       │   │   │   └───__pycache__
│   │       │   │   └───__pycache__
│   │       │   ├───_vendor
│   │       │   │   ├───cachecontrol
│   │       │   │   │   ├───caches
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───certifi
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───distlib
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───distro
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───idna
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───msgpack
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───packaging
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───pkg_resources
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───platformdirs
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───pygments
│   │       │   │   │   ├───filters
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───formatters
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───lexers
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───styles
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───pyproject_hooks
│   │       │   │   │   ├───_in_process
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───requests
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───resolvelib
│   │       │   │   │   ├───compat
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───rich
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───tomli
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───truststore
│   │       │   │   │   └───__pycache__
│   │       │   │   ├───urllib3
│   │       │   │   │   ├───contrib
│   │       │   │   │   │   ├───_securetransport
│   │       │   │   │   │   │   └───__pycache__
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───packages
│   │       │   │   │   │   ├───backports
│   │       │   │   │   │   │   └───__pycache__
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   ├───util
│   │       │   │   │   │   └───__pycache__
│   │       │   │   │   └───__pycache__
│   │       │   │   └───__pycache__
│   │       │   └───__pycache__
│   │       ├───pip-24.2.dist-info
│   │       ├───pycparser
│   │       │   ├───ply
│   │       │   │   └───__pycache__
│   │       │   └───__pycache__
│   │       └───pycparser-2.22.dist-info
│   └───Scripts
├───python
│   ├───logs
│   ├───security
│   │   └───__pycache__
│   ├───utils
│   │   └───__pycache__
│   └───__pycache__
├───SC_Project
│   ├───build
│   │   ├───classes
│   │   │   ├───C1
│   │   │   ├───C2
│   │   │   ├───Enc
│   │   │   ├───passwordutil
│   │   │   ├───S1
│   │   │   ├───sc_project
│   │   │   ├───SecureC1
│   │   │   └───SecureC2
│   │   ├───empty
│   │   └───generated-sources
│   │       └───ap-source-output
│   ├───dist
│   │   └───lib
│   ├───nbproject
│   │   └───private
│   ├───src
│   │   ├───C1
│   │   ├───C2
│   │   ├───Enc
│   │   ├───passwordutil
│   │   ├───S1
│   │   ├───sc_project
│   │   ├───SecureC1
│   │   └───SecureC2
│   └───test
└───ssl
    └───OpenSSL-Win64
        ├───bin
        │   ├───cnf
        │   └───PEM
        │       └───demoSRP
        ├───exp
        ├───include
        │   └───openssl
        ├───lib
        │   └───VC
        │       └───x64
        │           ├───MD
        │           ├───MDd
        │           ├───MT
        │           └───MTd
        └───tests
            ├───certs
            ├───ct
            ├───d2i-tests
            ├───fuzz
            ├───ocsp-tests
            ├───recipes
            │   ├───04-test_asn1_stable_parse_data
            │   ├───04-test_conf_data
            │   ├───04-test_params_conversion_data
            │   ├───04-test_pem_reading_data
            │   ├───04-test_pem_read_depr_data
            │   ├───10-test_bn_data
            │   ├───15-test_dsaparam_data
            │   │   ├───invalid
            │   │   └───valid
            │   ├───15-test_ecparam_data
            │   │   ├───invalid
            │   │   ├───noncanon
            │   │   └───valid
            │   ├───15-test_mp_rsa_data
            │   ├───15-test_rsapss_data
            │   ├───20-test_dhparam_check_data
            │   │   ├───invalid
            │   │   └───valid
            │   ├───20-test_dhparam_data
            │   ├───25-test_eai_data
            │   ├───25-test_pkcs7_data
            │   ├───25-test_rusext_data
            │   ├───30-test_defltfips
            │   ├───30-test_evp_data
            │   ├───30-test_evp_pkey_provided
            │   ├───30-test_pairwise_fail_data
            │   ├───61-test_bio_prefix_data
            │   ├───65-test_cmp_client_data
            │   ├───65-test_cmp_msg_data
            │   ├───65-test_cmp_protect_data
            │   ├───65-test_cmp_server_data
            │   ├───65-test_cmp_vfy_data
            │   ├───66-test_ossl_store_data
            │   ├───70-test_quic_multistream_data
            │   ├───75-test_quicapi_data
            │   ├───80-test_ca_data
            │   ├───80-test_ca_internals_data
            │   ├───80-test_cmp_http_data
            │   │   └───Mock
            │   ├───80-test_cmsapi_data
            │   ├───80-test_cms_data
            │   ├───80-test_ocsp_data
            │   ├───80-test_pkcs12_data
            │   ├───80-test_policy_tree_data
            │   ├───80-test_ssl_old_data
            │   ├───80-test_tsa_data
            │   ├───90-test_gost_data
            │   ├───90-test_includes_data
            │   │   ├───conf-includes
            │   │   └───conf-includes-prov
            │   ├───90-test_sslapi_data
            │   ├───90-test_store_cases_data
            │   ├───90-test_store_data
            │   ├───90-test_threads_data
            │   ├───91-test_pkey_check_data
            │   ├───95-test_external_cf_quiche_data
            │   ├───95-test_external_gost_engine_data
            │   ├───95-test_external_krb5_data
            │   ├───95-test_external_oqsprovider_data
            │   ├───95-test_external_pyca_data
            │   └───95-test_external_tlsfuzzer_data
            ├───smime-certs
            ├───smime-eml
            └───ssl-tests



## Setup and Running the Project

### Prerequisites

- Python 3.x
- OpenSSL

### Setting Up the Project



Run the Batch File:

Double-click the run.bat file or run it from the command prompt to set up and run the project.
The batch file will create a virtual environment, install the required dependencies, set the necessary environment variables, and run the application.
Configuration Files
The tls_setup.py script is responsible for generating self-signed certificates and configuring the TLS context for secure communication.

Log Files: 

Log files are generated and stored in the logs directory to keep track of the application's activities and errors.

Dependencies
The requirements.txt file contains the Python dependencies required for the project:

cryptography   

Acknowledgements
Thanks to the contributors of the cryptography library.
Thanks to the developers of OpenSSL.

Author : JAMAL_ALQBAIL