package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	rpcEndpoint := flag.String("rpc", "https://data-seed-prebsc-1-s1.binance.org:8545/", "RPC endpoint.")
	addr := flag.String("a", "0x9223f0630c598a200f99c5d4746531d10319a569", "Contract addr.")
	outFileName := flag.String("o", "contract.bin", "Output file name for bytecode.")
	flag.Parse()

	client, err := ethclient.Dial(*rpcEndpoint)
	if err != nil {
		log.Fatal(err)
	}
	contractAddress := common.HexToAddress(*addr)
	bytecode, err := client.CodeAt(context.Background(), contractAddress, nil) // nil is latest block
	if err != nil {
		log.Fatal(err)
	}

	// bytecode = bytes.ReplaceAll(bytecode, []byte{0x5F}, []byte{0x5B})
	// bytecode = bytes.ReplaceAll(bytecode, []byte{0x5F}, []byte{0x60})
	// bytecode = bytes.ReplaceAll(bytecode, []byte{0x5F}, []byte{0x60, 0x00})

	dumpFile, err := os.Create(*outFileName)
	if err != nil {
		log.Fatal(err)
	}
	dumpFile.Write(bytecode)
	fmt.Println(hex.EncodeToString(bytecode)) // 60806...10029
}
