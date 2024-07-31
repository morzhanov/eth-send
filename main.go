package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"gopkg.in/yaml.v2"
)

// Config struct for YAML
type Config struct {
	RPC     string         `yaml:"rpc"`
	Address string         `yaml:"address"`
	PK      string         `yaml:"pk"`
	Secret  string         `yaml:"secret"`
	Data    string         `yaml:"data"`
	Value   string         `yaml:"value"`
	To      string         `yaml:"to"`
	ChainID *big.Int       `yaml:"chainId"`
	Approve *ApproveConfig `yaml:"approve"`
}

// ApproveConfig struct for approval
type ApproveConfig struct {
	Token string `yaml:"token"`
	Limit int64  `yaml:"limit"`
}

func main() {
	// Read config
	config, err := readConfig("./config.yaml")
	if err != nil {
		log.Fatalf("Error reading config: %v", err)
	}
	fmt.Println("Config read successfully")

	// Initialize Ethereum client
	client, err := ethclient.Dial(config.RPC)
	if err != nil {
		log.Fatalf("Error creating Ethereum client: %v", err)
	}
	fmt.Println("Ethereum client initialized")

	// Decrypt private key
	decryptedKey, err := decryptPK(config.PK, config.Secret)
	if err != nil {
		log.Fatalf("Failed to decrypt private key: %v", err)
	}
	fmt.Println("Private key decrypted")

	// Convert private key
	privateKey, err := crypto.HexToECDSA(decryptedKey)
	if err != nil {
		log.Fatalf("Failed to convert private key: %v", err)
	}
	fmt.Println("Private key converted to ECDSA")

	// Prepare transaction data
	var txData []byte
	var txValue *big.Int
	if config.Approve != nil {
		txData = createApprovalData(config.Approve.Token, config.Approve.Limit)
	} else {
		txData = common.FromHex(config.Data)
	}
	txValue = new(big.Int)
	txValue.SetString(config.Value, 10)
	fmt.Printf("Transaction data prepared: %s\n", txData)
	fmt.Printf("Transaction value: %s\n", txValue.String())

	// Fetch nonce
	nonce, err := client.PendingNonceAt(context.Background(), common.HexToAddress(config.Address))
	if err != nil {
		log.Fatalf("Error fetching nonce: %v", err)
	}
	fmt.Printf("Nonce fetched: %d\n", nonce)

	// Fetch gas price and estimate gas
	baseGasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("Error fetching gas price: %v", err)
	}
	baseGas := new(big.Int).Set(baseGasPrice)
	maxPriorityFeePerGas := new(big.Int).SetUint64(1 * 1e9) // 1 Gwei
	fmt.Printf("Base gas price: %s\n", baseGasPrice.String())

	// Estimate gas limit
	to := common.HexToAddress(config.To)
	gasEstimate, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		From:     common.HexToAddress(config.Address),
		To:       &to,
		Gas:      0,
		GasPrice: baseGasPrice,
		Value:    txValue,
		Data:     txData,
	})
	if err != nil {
		log.Fatalf("Error estimating gas: %v", err)
	}
	gasLimit := new(big.Int).SetUint64(uint64(gasEstimate + gasEstimate/10))               // 10% buffer
	maxFeePerGas := new(big.Int).Set(baseGas).Add(baseGas, new(big.Int).SetUint64(20*1e9)) // 20 Gwei buffer
	fmt.Printf("Gas estimate: %d\n", gasEstimate)
	fmt.Printf("Gas limit: %s\n", gasLimit.String())
	fmt.Printf("Max fee per gas: %s\n", maxFeePerGas.String())

	// Compose transaction
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     nonce,
		GasFeeCap: maxFeePerGas,
		GasTipCap: maxPriorityFeePerGas,
		Gas:       gasLimit.Uint64(),
		To:        &to,
		Value:     txValue,
		Data:      txData,
	})
	fmt.Printf("Transaction composed: %+v\n", tx)

	// Sign transaction
	txHash := tx.Hash()
	signature, err := crypto.Sign(txHash.Bytes(), privateKey)
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}
	signedTx, err := tx.WithSignature(types.NewEIP155Signer(config.ChainID), signature)
	if err != nil {
		log.Fatalf("Error creating signed transaction: %v", err)
	}
	fmt.Println("Transaction signed")

	// Log RLP encoded transaction
	var buf bytes.Buffer
	if err := signedTx.EncodeRLP(&buf); err != nil {
		log.Fatalf("Error encoding transaction to RLP: %v", err)
	}
	fmt.Printf("Signed transaction RLP: %s\n", base64.StdEncoding.EncodeToString(buf.Bytes()))

	// Send transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatalf("Error sending transaction: %v", err)
	}
	fmt.Printf("Transaction sent! Hash: %s\n", signedTx.Hash().Hex())

	// Wait for receipt with polling
	var receipt *types.Receipt
	for {
		receipt, err = client.TransactionReceipt(context.Background(), signedTx.Hash())
		if err == nil && receipt != nil {
			break
		}
		time.Sleep(5 * time.Second) // wait before retrying
	}
	fmt.Printf("Transaction receipt received\n")
	fmt.Printf("Transaction status: %v\n", receipt.Status)
}

func readConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// decryptPK decrypts a base64 encoded AES encrypted private key
func decryptPK(encryptedPK, secret string) (string, error) {
	// Decode base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedPK)
	if err != nil {
		return "", err
	}

	// Generate key from secret
	key := generateKeyFromSecret(secret)

	// Decrypt
	plaintext, err := decrypt(encryptedBytes, key)
	if err != nil {
		return "", err
	}

	return plaintext, nil
}

// generateKeyFromSecret creates an AES key from the provided secret
func generateKeyFromSecret(secret string) []byte {
	h := sha1.New()
	h.Write([]byte(secret))
	key := md5.Sum(h.Sum(nil))
	return key[:]
}

// decrypt decrypts AES GCM encrypted data
func decrypt(encryptedData []byte, key []byte) (string, error) {
	// Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Get the nonce size
	nonceSize := aesGCM.NonceSize()

	// Extract the nonce from the encrypted data
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func createApprovalData(tokenAddress string, limit int64) []byte {
	// Create ERC20 approval data
	approvalABI, _ := abi.JSON(strings.NewReader(`[{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]`))
	data, _ := approvalABI.Pack("approve", common.HexToAddress(tokenAddress), new(big.Int).SetInt64(limit))
	return data
}