# My Cashu Nutshell Implementation

**Nutshell is a Chaumian Ecash wallet and mint for Bitcoin Lightning based on the Cashu protocol.**

Cashu is a free and open-source Ecash protocol that enables private and scalable transactions on Bitcoin's Lightning Network. It uses a variant of Chaumian blinding called Blind Diffie-Hellman Key Exchange to ensure privacy and security. This project is a custom implementation of the Nutshell wallet and mint, tailored to include a unique protocol for atomic token swaps.

## Features

- Bitcoin Lightning support
- Full compatibility with the Cashu protocol
- Standalone CLI wallet and mint server
- Support for multiple mints in a single wallet
- Custom protocol for atomic token swaps between mints and users

## My Protocol

This implementation introduces a custom protocol that uses adaptor signatures to enable atomic token swaps between different mints and users, such as Alice and Bob. The atomic swap is achieved through a proof locked in a P2PK contract and a P2PK multisig contract. Built on a modified Schnorr Signature scheme, the protocol ensures secure and trustless exchanges, enhancing interoperability and flexibility in the Cashu ecosystem.

## Installation

To set up the project, follow these steps:

1. **Install Python and dependencies**: Ensure you have Python 3.10+ installed. Install the required dependencies using `pip`:

   ```bash
   pip install -r requirements.txt
   ```

2. **Install Poetry**: If you don't have Poetry installed, run:

   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   echo export PATH="$HOME/.local/bin:$PATH" >> ~/.bashrc
   source ~/.bashrc
   ```

3. **Clone the repository**:

   ```bash
   git clone https://github.com/your-username/your-repo.git
   cd your-repo
   ```

4. **Install project dependencies with Poetry**:

   ```bash
   poetry install
   ```

## Running the Application

To run the wallet or mint, activate the Poetry virtual environment and use the appropriate commands.

1. **Activate Poetry environment**:

   ```bash
   poetry shell
   ```

2. **Run the wallet**: Check wallet information or balance:

   ```bash
   cashu info
   cashu balance
   ```

3. **Run the mint** (for testing): Ensure you have configured the `.env` file (see below). Then, start the mint:

   ```bash
   poetry run mint
   ```

## Configuration

To configure the mint, create a `.env` file based on the example below and adjust the settings as needed. The following configuration is tailored for Alice's mint, designed for testing atomic swaps in a local environment.

1. **Create the** `.env` **file on project root**:

   ```bash
   vim .env
   ```

2. **Use the following template for Alice's mint**:

   ```bash
   # Alice's Mint Config (Mint A)
   
   # Depuration
   DEBUG=FALSE
   
   # Data dir
   CASHU_DIR=./data_alice
   
   # Mint's Config Specs
   MINT_HOST=127.0.0.1
   MINT_PORT=3338
   MINT_LISTEN_PORT=3338
   MINT_DATABASE=data/mint
   
   # Disable Lightning for local environment
   LIGHTNING_ENABLED=false
   MINT_BACKEND_BOLT11_SAT=FakeWallet
   
   # Mint Info
   MINT_INFO_NAME="Alice Cashu Mint"
   MINT_INFO_DESCRIPTION="Mint A for atomic swap testing"
   MINT_INFO_DESCRIPTION_LONG="This is Alice's Cashu mint for testing atomic swaps between mints."
   MINT_INFO_CONTACT=[["email","alice@example.com"]]
   MINT_INFO_MOTD="Welcome to Alice's Mint"
   
   # Private Key (32 bytes)
   MINT_PRIVATE_KEY={}
   
   # Derivation path
   MINT_DERIVATION_PATH="m/0'/0'/0'"
   
   # Limits
   MINT_MAX_BALANCE=1000000
   MINT_MAX_PEG_IN=100000
   MINT_MAX_PEG_OUT=100000
   MINT_PEG_OUT_ONLY=FALSE
   
   # Advanced options
   TOR=FALSE
   MINT_RATE_LIMIT=FALSE
   MINT_REQUIRE_AUTH=FALSE
   ```

3. **Key adjustments**:

   - Replace `MINT_PRIVATE_KEY={}` with a secure 32-byte private key for your mint.
   - The `FakeWallet` backend (`MINT_BACKEND_BOLT11_SAT=FakeWallet`) is used for testing without a real Lightning network.
   - For a public test mint, set `MINT_URL=https://testnut.cashu.space` instead of the local configuration.

*Warning: The public test mint is for demonstration purposes only. Satoshis are not real.*

## Contributing

Contributions are welcome! Please see the contribution guide for details.