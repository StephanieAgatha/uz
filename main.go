package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	rpcURL = "https://rpc-testnet.unit0.dev"
)

func initLogger() *zap.SugaredLogger {
	config := zap.NewProductionConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02T15:04:05.000-0700")
	config.EncoderConfig.EncodeCaller = nil
	config.OutputPaths = []string{"stdout"}
	config.EncoderConfig.EncodeDuration = zapcore.StringDurationEncoder
	config.Encoding = "console"
	config.DisableStacktrace = true
	config.EncoderConfig.ConsoleSeparator = " "

	logger, err := config.Build(zap.AddCallerSkip(1))
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	return logger.Sugar()
}

func generateRandomAmount() *big.Int {
	// Generate a random number between 10 and 11
	min := big.NewInt(10)
	max := new(big.Int).SetInt64(11)
	diff := new(big.Int).Sub(max, min)
	n, _ := rand.Int(rand.Reader, diff)
	n.Add(n, min)

	// Convert to 0.00001 to 0.00002 UNIT0
	amount := new(big.Int).Mul(n, big.NewInt(1000000000000))

	return amount
}

func weiToUnit0(wei *big.Int) *big.Float {
	return new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
}

func formatPrivateKey(privateKeyString string) string {
	privateKeyString = strings.TrimSpace(privateKeyString)

	if strings.HasPrefix(privateKeyString, "0x") {
		privateKeyString = privateKeyString[2:]
	}

	return privateKeyString
}

func processWallet(privateKeyString string, client *ethclient.Client, logger *zap.SugaredLogger, numWallets int) error {
	privateKeyString = formatPrivateKey(privateKeyString)

	privateKey, err := crypto.HexToECDSA(privateKeyString)
	if err != nil {
		return fmt.Errorf("failed to load private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to cast public key")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	balance, err := client.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		return fmt.Errorf("failed to get balance: %v", err)
	}

	balanceInUNIT0 := weiToUnit0(balance)
	logger.Infof("Balance of wallet %s: %.6f UNIT0", fromAddress.Hex(), balanceInUNIT0)

	//get the nonce
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return fmt.Errorf("failed to get the nonce: %v", err)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get chainID: %v", err)
	}

	gasLimit := uint64(21000)
	maxFeePerGas := new(big.Int).Mul(big.NewInt(1233269), big.NewInt(1000))
	maxPriorityFeePerGas := new(big.Int).Set(maxFeePerGas)

	remainingWallets := numWallets
	for remainingWallets > 0 {
		value := generateRandomAmount()

		gasCost := new(big.Int).Mul(maxFeePerGas, big.NewInt(int64(gasLimit)))
		totalCost := new(big.Int).Add(value, gasCost)

		if balance.Cmp(totalCost) < 0 {
			logger.Errorf("Insufficient balance for transaction. Required: %.6f UNIT0, Available: %.6f UNIT0",
				weiToUnit0(totalCost), weiToUnit0(balance))
			logger.Infof("Transaction amount: %.6f UNIT0, Gas cost: %.6f UNIT0",
				weiToUnit0(value), weiToUnit0(gasCost))
			return fmt.Errorf("insufficient balance")
		}

		newPrivateKey, err := crypto.GenerateKey()
		if err != nil {
			logger.Errorf("Failed to generate new private key: %v", err)
			continue
		}

		newAddress := crypto.PubkeyToAddress(newPrivateKey.PublicKey)

		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     nonce,
			GasTipCap: maxPriorityFeePerGas,
			GasFeeCap: maxFeePerGas,
			Gas:       gasLimit,
			To:        &newAddress,
			Value:     value,
			Data:      nil,
		})

		signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
		if err != nil {
			logger.Errorf("Failed to sign the transaction: %v", err)
			continue
		}

		err = client.SendTransaction(context.Background(), signedTx)
		if err != nil {
			switch {
			case strings.Contains(err.Error(), "Replacement transaction underpriced"):
				logger.Error("Got an error: Replacement transaction underpriced. Retrying in 2 seconds...")
				time.Sleep(2 * time.Second)
				continue
			case strings.Contains(err.Error(), "Nonce too low"):
				logger.Error("Nonce too low, retrying with new nonce...")
				nonce, err = client.PendingNonceAt(context.Background(), fromAddress)
				if err != nil {
					logger.Error("Failed to get nonce")
				}
				continue
			case strings.Contains(err.Error(), "Upfront cost exceeds account balance"):
				logger.Error("Your wallet has low balance")
				return fmt.Errorf("low balance")
			case strings.Contains(err.Error(), "502 Bad Gateway"):
				logger.Error("Got an error 502 Bad Gateway. Retrying in 3 seconds...")
				time.Sleep(3 * time.Second)
				continue
			case strings.Contains(err.Error(), "503 Service Temporarily Unavailable"):
				logger.Error("Got an error 503 Service Temporarily Unavailable. Retrying in 5 seconds...")
				time.Sleep(5 * time.Second)
				continue
			case strings.Contains(err.Error(), "Known transaction"):
				logger.Error("Got an error: Known transaction. Retrying in 3 seconds...")
				time.Sleep(3 * time.Second)
				continue
			default:
				logger.Errorf("Failed to send the transaction: %v", err)
				continue
			}
		}

		logger.Infof("Transaction sent: hash=%s, address=%s, amount=%.6f UNIT0, nonce=%d",
			signedTx.Hash().Hex(), newAddress.Hex(), weiToUnit0(value), nonce)
		logger.Info("Sleeping 22 seconds ....")
		time.Sleep(22 * time.Second)

		balance.Sub(balance, totalCost)
		nonce++
		remainingWallets--
	}

	return nil
}

func main() {
	logger := initLogger()
	defer logger.Sync()

	startTime := time.Now()

	data, err := ioutil.ReadFile("pk.txt")
	if err != nil {
		logger.Errorf("Failed to read pk.txt file: %v", err)
		return
	}
	privateKeyStrings := strings.Split(string(data), "\n")

	var validPrivateKeys []string
	for _, pk := range privateKeyStrings {
		pk = strings.TrimSpace(pk)
		if pk != "" {
			validPrivateKeys = append(validPrivateKeys, pk)
		}
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		logger.Errorf("Failed to connect to rpc url: %v", err)
		return
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("How many wallets do you want to generate: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	numWallets, err := strconv.Atoi(input)
	if err != nil {
		logger.Errorf("Invalid number of wallets: %v", err)
		return
	}

	//sequentially
	for i, privateKeyString := range validPrivateKeys {
		logger.Infof("Processing private key %d of %d", i+1, len(validPrivateKeys))

		err := processWallet(privateKeyString, client, logger, numWallets)
		if err != nil {
			logger.Errorf("Failed to process wallet with private key %d: %v", i+1, err)
			//continue
			continue
		}

		logger.Infof("Completed processing private key %d of %d", i+1, len(validPrivateKeys))

		if i < len(validPrivateKeys)-1 {
			logger.Info("Waiting 30 seconds before processing next private key...")
			time.Sleep(30 * time.Second)
		}
	}

	endTime := time.Now()
	duration := endTime.Sub(startTime).Seconds()
	logger.Infof("All transactions completed in %.2f seconds", duration)
}
