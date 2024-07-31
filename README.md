# eth-send

A Go application to compose, sign, and send Ethereum transactions based on a configuration file. The app also supports token approvals if specified.

### Features

- Reads transaction details from a YAML configuration file.
- Decodes an AES-encrypted private key.
- Composes transactions with automatic nonce fetching.
- Estimates gas limit and price with a buffer.
- Signs and sends Ethereum transactions.
- Supports token approval transactions.

### Configuration

Create a `config.yaml` file based on the provided example below. Place this file in the same directory as the application.

### Example `config.yaml`

```yaml
rpc: "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"
address: "0xYourAddress"
pk: "encryptedPrivateKeyInBase64"
secret: "yourSecretForDecrypting"
data: "0xYourTransactionData"
value: "0"
to: "0xRecipientAddress"
chainId: 1
approve:
  token: "0xTokenAddress"
  limit: 1000000
```

- `rpc`: Ethereum RPC URL.
- `address`: Your Ethereum address.
- `pk`: AES-encoded private key (base64).
- `secret`: Secret for AES decryption.
- `data`: Transaction data (optional, used if approve is not set).
- `value`: Transaction value in wei (default: 0).
- `to`: Recipient address.
- `chainId`: eth-like chain id
- `approve`: Optional. If set, an ERC20 token approval transaction will be composed and sent.
    - `token`: Token address to approve.
    - `limit`: Amount of tokens to approve.

### Execution
To build and run the application, follow these steps:

#### Build the Application

```bash
make build
```
This will compile the Go source code into an executable binary named eth-send.

#### Run the application:

```bash
make run
```

This will execute the eth-send binary. The application will perform the following steps:
- Read Configuration: The application will read the configuration from config.yaml.
- Decode Private Key: The AES-encrypted private key will be decrypted using the provided secret.
- Fetch Nonce: The current nonce for the provided Ethereum address will be fetched from the Ethereum network.
- Estimate Gas: The application will estimate the gas limit and gas price for the transaction, applying a buffer to ensure successful execution.
- Compose Transaction: Based on the configuration, the transaction will be composed. If the approve field is set, an ERC20 token approval transaction will be created; otherwise, the specified data will be used for a standard transaction.
- Sign Transaction: The transaction will be signed using the decoded private key.
- Send Transaction: The signed transaction will be sent to the Ethereum network.
- Log Results: The application will log detailed information about each step, including the transaction hash and status.

#### Clean up build artifacts (optional):

```bash
make clean
```
This will remove the eth-send binary from the directory.

### Notes
Ensure you have the necessary Go modules installed:

```bash
go mod tidy
```

Modify the config.yaml file with appropriate values before running the application.
