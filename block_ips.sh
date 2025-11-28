#!/bin/bash

BLOCKLIST_FILE="blocklist.txt"
NFT_TABLE="filter"
NFT_CHAIN="ip_blocklist"
NFT_SET="blocked_ips"

# Step 1: Clean old table/chain (optional safety)
sudo nft delete table inet $NFT_TABLE 2>/dev/null

# Step 2: Create table and chain
sudo nft add table inet $NFT_TABLE 2>/dev/null
sudo nft add chain inet $NFT_TABLE $NFT_CHAIN '{ type filter hook prerouting priority 0; policy accept; }'

# Step 3: Create the IP set
sudo nft delete set inet $NFT_TABLE $NFT_SET 2>/dev/null
sudo nft add set inet $NFT_TABLE $NFT_SET '{ type ipv4_addr; flags interval; }'

# Step 4: Filter and format the IPs
IP_LIST=$(grep -vE '^\s*#|^\s*$' "$BLOCKLIST_FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | paste -sd, -)

echo "Entries: { $IP_LIST }"

# Step 5: Insert IPs into the nft set (quoted properly)
sudo nft add element inet $NFT_TABLE $NFT_SET "{ $IP_LIST }"

# Step 6: Add drop rule if not already present
if ! sudo nft list chain inet $NFT_TABLE $NFT_CHAIN | grep -q "@$NFT_SET"; then
    sudo nft insert rule inet $NFT_TABLE $NFT_CHAIN ip saddr @$NFT_SET log flags ip options prefix \"LOGRIP=\" drop
fi

echo ""
echo "IP blocklist applied successfully."
echo " Confirm using: > sudo nft list ruleset"
echo " Examine logs:  > sudo journalctl -k | grep \"LOGRIP\""
echo ""

