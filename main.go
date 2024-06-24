package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"log"
	"math"
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

func main() {
	data, err := ioutil.ReadFile("pk.txt")
	if err != nil {
		log.Fatalf("Failed to read pk.txt: %v", err)
	}
	privateKeyString := strings.TrimSpace(string(data))

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privateKey, err := crypto.HexToECDSA(privateKeyString)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Failed to cast public key to ECDSA: %v", err)
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	//get balance
	balance, err := client.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		log.Fatalf("Failed to get balance: %v", err)
	}

	balanceInUNIT0 := new(big.Float).Quo(new(big.Float).SetInt(balance), big.NewFloat(math.Pow10(18)))
	fmt.Printf("Balance wallet %s : %f UNIT0\n", fromAddress.Hex(), balanceInUNIT0)

	// Get the nonce
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("Failed to get the nonce : %v", err)
	}
	value := big.NewInt(100000000000000)
	gasLimit := uint64(21000) //gas limit

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("Failed to suggest gas price: %v", err)
	}
	chainID := big.NewInt(88817)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("How many wallets do you want to generate: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	numWallets, err := strconv.Atoi(input)
	if err != nil {
		log.Fatalf("Invalid number of wallets: %v", err)
	}

	for i := 0; i < numWallets; i++ {
		newPrivateKey, err := crypto.GenerateKey()
		if err != nil {
			log.Fatalf("Failed to generate new private key: %v", err)
		}

		newAddress := crypto.PubkeyToAddress(newPrivateKey.PublicKey)

		for {
			// create tx
			tx := types.NewTransaction(nonce+uint64(i), newAddress, value, gasLimit, gasPrice, nil)

			// sign in
			signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
			if err != nil {
				log.Fatalf("Failed to sign the transaction: %v", err)
			}

			// send tx
			err = client.SendTransaction(context.Background(), signedTx)
			if err != nil {
				if strings.Contains(err.Error(), "Replacement transaction underpriced") {
					fmt.Println("Got an error :(, Retry transaction...")
					time.Sleep(2 * time.Second)
					continue
				}
				if strings.Contains(err.Error(), "Nonce too low") {
					fmt.Println("Nonce too low, retrying with new nonce...")
					nonce, err = client.PendingNonceAt(context.Background(), fromAddress)
					if err != nil {
						log.Fatalf("Failed to get the nonce : %v", err)
					}
					continue
				}
				log.Fatalf("Failed to send the transaction: %v", err)
			}

			fmt.Printf("Transaction sent to %s: %s\n", newAddress.Hex(), signedTx.Hash().Hex())
			nonce++
			break
		}
	}
}
