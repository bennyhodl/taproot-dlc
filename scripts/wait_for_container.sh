#!/bin/bash

# Wait for the Bitcoin container to be running
while [ "`docker inspect -f {{.State.Status}} $1`" != "running" ]; do
     echo "Waiting for container $1 to be running..."
     sleep 2;
done

echo "Container $1 is running. Checking wallet setup..."

# Wait for Bitcoin RPC to be ready
echo "Waiting for Bitcoin RPC to be ready..."
until docker exec bitcoin bitcoin-cli --rpcport=18443 --rpcuser=ddk --rpcpassword=ddk getblockchaininfo > /dev/null 2>&1; do
    echo "Bitcoin RPC not ready yet, waiting..."
    sleep 2
done

echo "Bitcoin RPC is ready. Checking for taproot-dlc wallet..."

# Check if taproot-dlc wallet exists
WALLET_LIST=$(docker exec bitcoin bitcoin-cli --rpcport=18443 --rpcuser=ddk --rpcpassword=ddk listwallets 2>/dev/null || echo "[]")
WALLET_EXISTS=$(echo "$WALLET_LIST" | grep -c "taproot-dlc" 2>/dev/null || echo "0")
WALLET_EXISTS=$(echo "$WALLET_EXISTS" | tr -d '\n\r' | head -n1)

if [ "$WALLET_EXISTS" -eq "0" ]; then
    echo "taproot-dlc wallet not found. Creating wallet..."
    
    # Create the taproot-dlc wallet
    docker exec bitcoin bitcoin-cli --rpcport=18443 --rpcuser=ddk --rpcpassword=ddk createwallet "taproot-dlc" false false "" false true true
    
    if [ $? -eq 0 ]; then
        echo "taproot-dlc wallet created successfully."
        
        # Check current block count
        CURRENT_BLOCKS=$(docker exec bitcoin bitcoin-cli --rpcport=18443 --rpcuser=ddk --rpcpassword=ddk -rpcwallet=taproot-dlc getblockcount)
        echo "Current block count: $CURRENT_BLOCKS"
        
        # Generate 200 blocks if this is a new node (block count is very low)
        if [ "$CURRENT_BLOCKS" -lt "10" ]; then
            echo "New node detected (block count: $CURRENT_BLOCKS). Generating 200 blocks..."
            
            # Get a new address for mining rewards
            MINING_ADDRESS=$(docker exec bitcoin bitcoin-cli --rpcport=18443 --rpcuser=ddk --rpcpassword=ddk -rpcwallet=taproot-dlc getnewaddress)
            echo "Mining address: $MINING_ADDRESS"
            
            # Generate 200 blocks
            docker exec bitcoin bitcoin-cli --rpcport=18443 --rpcuser=ddk --rpcpassword=ddk -rpcwallet=taproot-dlc generatetoaddress 200 "$MINING_ADDRESS"
            
            NEW_BLOCK_COUNT=$(docker exec bitcoin bitcoin-cli --rpcport=18443 --rpcuser=ddk --rpcpassword=ddk -rpcwallet=taproot-dlc getblockcount)
            echo "Generated 200 blocks. New block count: $NEW_BLOCK_COUNT"
        else
            echo "Node already has blocks ($CURRENT_BLOCKS). Skipping block generation."
        fi
    else
        echo "Failed to create taproot-dlc wallet."
        exit 1
    fi
else
    echo "taproot-dlc wallet already exists."
    
    # Load the wallet if it's not loaded
    docker exec bitcoin bitcoin-cli --rpcport=18443 --rpcuser=ddk --rpcpassword=ddk loadwallet "taproot-dlc" > /dev/null 2>&1 || echo "Wallet already loaded or failed to load."
fi

echo "Wallet setup complete. taproot-dlc wallet is ready."

