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
	"sync"
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
	// Generate a random number between 100 and 110
	min := big.NewInt(10)
	max := new(big.Int).SetInt64(11)
	diff := new(big.Int).Sub(max, min)
	n, _ := rand.Int(rand.Reader, diff)
	n.Add(n, min)

	// Convert to 0.00001 to 0.00002 UNIT0
	amount := new(big.Int).Mul(n, big.NewInt(1000000000000)) // Multiply by 10^12

	return amount
}

func weiToUnit0(wei *big.Int) *big.Float {
	return new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
}

func processWallet(privateKeyString string, client *ethclient.Client, logger *zap.SugaredLogger, numWallets int, wg *sync.WaitGroup, remainingWallets *int) {
	defer wg.Done()

	privateKey, err := crypto.HexToECDSA(privateKeyString)
	if err != nil {
		logger.Errorf("Failed to load private key: %v", err)
		return
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		logger.Errorf("Failed to cast public key: %v", err)
		return
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Get balance
	balance, err := client.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		logger.Errorf("Failed to get balance: %v", err)
		return
	}

	balanceInUNIT0 := weiToUnit0(balance)
	logger.Infof("Balance of wallet %s: %.6f UNIT0", fromAddress.Hex(), balanceInUNIT0)

	// Get the nonce
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		logger.Errorf("Failed to get the nonce: %v", err)
		return
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		logger.Errorf("Failed to get chainID: %v", err)
		return
	}

	// Gas settings
	gasLimit := uint64(21000)

	// MaxFeePerGas: 0.001233269 Gwei
	maxFeePerGas := new(big.Int).Mul(big.NewInt(1233269), big.NewInt(1000)) // 0.001233269 * 10^9

	// MaxPriorityFeePerGas: 0.001233269 Gwei (same as MaxFeePerGas in this case)
	maxPriorityFeePerGas := new(big.Int).Set(maxFeePerGas)

	for *remainingWallets > 0 {
		// Generate random amount
		value := generateRandomAmount()

		// Calculate total cost
		gasCost := new(big.Int).Mul(maxFeePerGas, big.NewInt(int64(gasLimit)))
		totalCost := new(big.Int).Add(value, gasCost)

		// Check if we have enough balance
		if balance.Cmp(totalCost) < 0 {
			logger.Errorf("Insufficient balance for transaction. Required: %.6f UNIT0, Available: %.6f UNIT0",
				weiToUnit0(totalCost), weiToUnit0(balance))
			logger.Infof("Transaction amount: %.6f UNIT0, Gas cost: %.6f UNIT0",
				weiToUnit0(value), weiToUnit0(gasCost))
			return
		}

		newPrivateKey, err := crypto.GenerateKey()
		if err != nil {
			logger.Errorf("Failed to generate new private key: %v", err)
			continue
		}

		newAddress := crypto.PubkeyToAddress(newPrivateKey.PublicKey)

		// create EIP-1559 tx
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

		// sign tx
		signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
		if err != nil {
			logger.Errorf("Failed to sign the transaction: %v", err)
			continue
		}

		// send tx
		err = client.SendTransaction(context.Background(), signedTx)
		if err != nil {
			// handle specific errors
			switch {
			case strings.Contains(err.Error(), "Replacement transaction underpriced"):
				logger.Errorf("Got an error: Replacement transaction underpriced. Retrying in 2 seconds...")
				time.Sleep(2 * time.Second)
				continue
			case strings.Contains(err.Error(), "Nonce too low"):
				logger.Errorf("Nonce too low, retrying with new nonce...")
				nonce, err = client.PendingNonceAt(context.Background(), fromAddress)
				if err != nil {
					logger.Errorf("Failed to get nonce: %v", err)
				}
				continue
			case strings.Contains(err.Error(), "Upfront cost exceeds account balance"):
				logger.Errorf("Your wallet has low balance: %v", err)
				return
			case strings.Contains(err.Error(), "502 Bad Gateway"):
				logger.Errorf("Got an error 502 Bad Gateway. Retrying in 3 seconds...")
				time.Sleep(3 * time.Second)
				continue
			case strings.Contains(err.Error(), "503 Service Temporarily Unavailable"):
				logger.Errorf("Got an error 503 Service Temporarily Unavailable. Retrying in 5 seconds...")
				time.Sleep(5 * time.Second)
				continue
			case strings.Contains(err.Error(), "Known transaction"):
				logger.Errorf("Got an error: Known transaction. Retrying in 3 seconds...")
				time.Sleep(3 * time.Second)
				continue
			default:
				logger.Errorf("Failed to send the transaction: %v", err)
				continue
			}
		}

		logger.Infof("Transaction sent: hash=%s, address=%s, amount=%.6f UNIT0, nonce=%d",
			signedTx.Hash().Hex(), newAddress.Hex(), weiToUnit0(value), nonce)
		logger.Info("Sleeping 8 seconds ....")
		time.Sleep(8 * time.Second)

		// Update balance and nonce
		balance.Sub(balance, totalCost)
		nonce++
		*remainingWallets--
		if *remainingWallets <= 0 {
			break
		}
	}
}
func main() {
	logger := initLogger()
	defer logger.Sync()

	//set start time
	startTime := time.Now()

	data, err := ioutil.ReadFile("pk.txt")
	if err != nil {
		logger.Errorf("Failed to read pk.txt file: %v", err)
		return
	}
	privateKeyStrings := strings.Split(string(data), "\n")

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

	var wg sync.WaitGroup
	remainingWallets := numWallets

	for _, privateKeyString := range privateKeyStrings {
		privateKeyString = strings.TrimSpace(strings.ReplaceAll(privateKeyString, "\r", ""))
		if privateKeyString == "" {
			continue // skip
		}

		wg.Add(1)
		go processWallet(privateKeyString, client, logger, numWallets, &wg, &remainingWallets)
	}
	wg.Wait()

	endTime := time.Now()
	duration := endTime.Sub(startTime).Seconds()
	logger.Infof("All transactions completed in %.2f seconds", duration)
}
