package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	"math"
	"math/big"
	"math/rand"
	"net/http"
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

func initLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
}

func processWallet(privateKeyString string, client *ethclient.Client) {
	privateKey, err := crypto.HexToECDSA(privateKeyString)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load private key")
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Error().Msgf("Failed cat pubkey %v", err)
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Get balance
	balance, err := client.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get balance")
	}

	balanceInUNIT0 := new(big.Float).Quo(new(big.Float).SetInt(balance), big.NewFloat(math.Pow10(18)))
	log.Info().Msgf("balance wallet %s : %f UNITO", fromAddress.Hex(), balanceInUNIT0)

	// Get the nonce
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Error().Msg("Failed to get the nonce")
	}
	gasLimit := uint64(21000) // gas limit

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Error().Msg("Failed to suggest gas price")
	}
	chainID := big.NewInt(88817)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("How many wallets do you want to generate: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	numWallets, err := strconv.Atoi(input)
	if err != nil {
		log.Error().Msgf("Invalid number of wallets %v", err)
	}

	fmt.Print("Input your Authorization header value : ")
	headerValue, _ := reader.ReadString('\n')
	headerValue = strings.TrimSpace(headerValue)

	rand.Seed(time.Now().UnixNano())
	minValue := big.NewInt(10000000000000)
	maxValue := big.NewInt(9000000000000)

	for i := 0; i < numWallets; i++ {
		newPrivateKey, err := crypto.GenerateKey()
		if err != nil {
			log.Error().Msgf("Failed to generate new private key %v", err)
		}

		newAddress := crypto.PubkeyToAddress(newPrivateKey.PublicKey)

		for {
			value := new(big.Int).Add(minValue, big.NewInt(rand.Int63n(maxValue.Int64())))
			// create tx
			tx := types.NewTransaction(nonce+uint64(i), newAddress, value, gasLimit, gasPrice, nil)

			// sign in
			signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
			if err != nil {
				log.Error().Msg("Failed to sign the transaction")
			}

			// send tx
			err = client.SendTransaction(context.Background(), signedTx)
			if err != nil {
				// handle specific errors
				switch {
				case strings.Contains(err.Error(), "Replacement transaction underpriced"):
					log.Error().Msg("Got an error :(, Retry transaction...")
					time.Sleep(2 * time.Second)
					continue
				case strings.Contains(err.Error(), "Nonce too low"):
					log.Error().Msg("Nonce too low, retrying with new nonce...")
					nonce, err = client.PendingNonceAt(context.Background(), fromAddress)
					if err != nil {
						log.Error().Msg("Failed to get nonce")
					}
					continue
				case strings.Contains(err.Error(), "Upfront cost exceeds account balance"):
					log.Error().Msg("Your wallet has low balance")
					continue
				case strings.Contains(err.Error(), "502 Bad Gateway"):
					log.Error().Msg("Got an error 502 Bad Gateway. Retrying in 3 seconds...")
					time.Sleep(3 * time.Second)
					continue
				case strings.Contains(err.Error(), "503 Service Temporarily Unavailable"):
					log.Error().Msg("Got an error 503 Service Temporarily Unavailable. Retrying in 5 seconds...")
					time.Sleep(5 * time.Second)
					continue
				case strings.Contains(err.Error(), "Known transaction"):
					log.Error().Msg("Got an error, retrying in 3 seconds...")
					time.Sleep(3 * time.Second)
					continue
				default:
					log.Error().Msg("Failed to send the transaction")
				}
			}
			log.Info().Str("hash", signedTx.Hash().Hex()).Str("address", newAddress.Hex()).Msg("Transaction sent !")
			log.Info().Msg("Sleeping 8 seconds ....")
			time.Sleep(8 * time.Second)

			if headerValue != "" {
				GetTxProgress(headerValue)
			}
			nonce++
			break
		}
	}
	fmt.Println("========================================")
}

func GetTxProgress(headerValuee string) {
	url := "https://api.units.network/missions?filter%5Bprogress%5D=true&filter%5Brewards%5D=true&filter%5BcompletedPercent%5D=true&filter%5Bhidden%5D=false&filter%5Bdate%5D=2024-06-27T02:53:07.826Z&filter%5Bid%5D=3b5d3612-13a8-4afd-b978-2fbf8d567a5b"
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return
	}

	req.Header.Add("Authorization", headerValuee)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println(err)
		return
	}

	if data, ok := response["data"].([]interface{}); ok {
		if len(data) > 0 {
			if mission, ok := data[0].(map[string]interface{}); ok {
				if progress, ok := mission["progress"].(string); ok {
					fmt.Println("Total Transaction :", progress)
				} else {
					fmt.Println(err)
				}
			}
		} else {
			fmt.Println("No data found", err)
		}
	} else {
		fmt.Println("Data key not found or not an array", err)
	}
}

func main() {
	initLogger()

	//set start time
	startTime := time.Now()

	data, err := ioutil.ReadFile("pk.txt")
	if err != nil {
		log.Error().Err(err).Msg("Failed to read pk.txt file")
	}
	privateKeyStrings := strings.Split(string(data), "\n")

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to rpc url")
	}

	var wg sync.WaitGroup
	for _, privateKeyString := range privateKeyStrings {
		privateKeyString := strings.TrimSpace(strings.ReplaceAll(privateKeyString, "\r", ""))
		if privateKeyString == "" {
			continue // skip
		}

		wg.Add(1)
		go func(privateKeyString string) {
			defer wg.Done()
			processWallet(privateKeyString, client)
		}(privateKeyString)
	}
	wg.Wait()

	endTime := time.Now()
	duration := endTime.Sub(startTime).Seconds()
	log.Info().Msgf("All transaction completed in %2.f seccond", duration)
}
