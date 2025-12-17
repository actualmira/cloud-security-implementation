#!/bin/bash
# firewall-block.sh - Wazuh 4.x+ format with JSON input
# Compatible with Wazuh 4.0+

LOCAL=`dirname $0`
cd $LOCAL
cd ../
PWD=`pwd`
LOG="/var/ossec/logs/active-responses.log"

# Logging function
log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') firewall-block: $1" >> ${LOG}
}

log "=== Script started ==="

# Read JSON input from stdin
read INPUT_JSON
log "Received input: $INPUT_JSON"

# Parse JSON - try jq first, fallback to grep/sed
if command -v jq &> /dev/null; then
    ACTION=$(echo "$INPUT_JSON" | jq -r '.command' 2>/dev/null)
    SRCIP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip' 2>/dev/null)

    # Fallback path structure
    if [ -z "$SRCIP" ] || [ "$SRCIP" = "null" ]; then
        SRCIP=$(echo "$INPUT_JSON" | jq -r '.alert.data.srcip' 2>/dev/null)
    fi
else
    # Manual parsing without jq
    ACTION=$(echo "$INPUT_JSON" | grep -o '"command":"[^"]*"' | cut -d'"' -f4)
    SRCIP=$(echo "$INPUT_JSON" | grep -o '"srcip":"[^"]*"' | cut -d'"' -f4)
    log "Parsing without jq: ACTION=$ACTION, SRCIP=$SRCIP"
fi

# Validate inputs
if [ -z "$SRCIP" ] || [ "$SRCIP" = "null" ]; then
    log "ERROR: No source IP found in input"
    log "Input was: $INPUT_JSON"
    exit 1
fi

if [ -z "$ACTION" ]; then
    # Default to 'add' if no action specified
    ACTION="add"
    log "No action specified, defaulting to: add"
fi

log "Parsed - ACTION: $ACTION, SRCIP: $SRCIP"

# Validate IP format
if ! echo "$SRCIP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
    log "ERROR: Invalid IP format: $SRCIP"
    exit 1
fi

# Check if iptables exists
if ! command -v iptables &> /dev/null; then
    log "ERROR: iptables not found"
    exit 1
fi

# Execute action
case "$ACTION" in
    add)
        # Check if already blocked
        if iptables -C INPUT -s "$SRCIP" -j DROP 2>/dev/null; then
            log "IP $SRCIP is already blocked"
        else
            # Block the IP
            iptables -I INPUT -s "$SRCIP" -j DROP 2>&1 | tee -a ${LOG}
            if [ ${PIPESTATUS[0]} -eq 0 ]; then
                log "SUCCESS: Blocked IP $SRCIP"
            else
                log "ERROR: Failed to block IP $SRCIP"
                exit 1
            fi
        fi
        ;;
    delete)
        # Check if blocked
        if iptables -C INPUT -s "$SRCIP" -j DROP 2>/dev/null; then
            # Unblock the IP
            iptables -D INPUT -s "$SRCIP" -j DROP 2>&1 | tee -a ${LOG}
            if [ ${PIPESTATUS[0]} -eq 0 ]; then
                log "SUCCESS: Unblocked IP $SRCIP"
            else
                log "ERROR: Failed to unblock IP $SRCIP"
                exit 1
            fi
        else
            log "IP $SRCIP was not blocked"
        fi
        ;;
    *)
        log "ERROR: Unknown action: $ACTION"
        exit 1
        ;;
esac

log "=== Script completed ==="
exit 0

