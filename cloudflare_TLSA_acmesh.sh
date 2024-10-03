#!/bin/bash

# Ensure required environment variables are set
required_env_vars=("KEY_FILE" "KEY_FILE_NEXT" "ZONE_ID" "API_TOKEN" "DOMAIN")
for var in "${required_env_vars[@]}"; do
  if [[ -z "${!var}" ]]; then
    echo "Error: $var environment variable is not defined" >&2
    exit 1
  fi
done

# Set default port and protocol from environment variables, or use default values
PORT=${PORT:-25}
PROTOCOL=${PROTOCOL:-"tcp"}
API_URL="https://api.cloudflare.com/client/v4/zones"
USAGE=3
SELECTOR=1
MATCHING_TYPE=1

# Logging function
log() {
  echo "$(date) - $1"
}

# Function to generate certificate hash
generate_cert() {
  key_file="$1"
  
  if [[ ! -f "$key_file" ]]; then
    echo "Error: Key file $key_file does not exist" >&2
    exit 1
  fi

  # Extract public key from the private key
  pub_key=$(openssl rsa -in "$key_file" -pubout 2>/dev/null)
  if [[ $? -ne 0 ]]; then
    echo "Error: Failed to extract public key from $key_file" >&2
    exit 1
  fi

  # Hash the public key with SHA256
  cert_hash=$(echo "$pub_key" | openssl rsa -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -binary | xxd -p -c 256)
  
  echo "$cert_hash"
}

# Function to get TLSA records
get_tlsa_records() {
  zone_id="$1"
  api_token="$2"
  domain="$3"
  
  log "Fetching TLSA records for domain: $domain"
  url="${API_URL}/${zone_id}/dns_records?name=_${PORT}._${PROTOCOL}.${domain}"
  response=$(curl -s -X GET -H "Authorization: Bearer $api_token" "$url")
  
  echo "$response"
}

# Function to add TLSA record
add_tlsa_record() {
  zone_id="$1"
  api_token="$2"
  domain="$3"
  cert_hash="$4"

  log "Adding TLSA record with cert hash: $cert_hash"
  url="${API_URL}/${zone_id}/dns_records"
  payload=$(cat <<EOF
{
  "type": "TLSA",
  "name": "_${PORT}._${PROTOCOL}.${domain}",
  "data": {
    "usage": $USAGE,
    "selector": $SELECTOR,
    "matching_type": $MATCHING_TYPE,
    "certificate": "$cert_hash"
  }
}
EOF
)

  curl -s -X POST -H "Authorization: Bearer $api_token" -H "Content-Type: application/json" \
    -d "$payload" "$url"
}

# Function to modify existing TLSA record
modify_tlsa_record() {
  zone_id="$1"
  api_token="$2"
  domain="$3"
  cert_hash="$4"
  record_id="$5"

  log "Modifying TLSA record $record_id with cert hash: $cert_hash"
  url="${API_URL}/${zone_id}/dns_records/$record_id"
  payload=$(cat <<EOF
{
  "type": "TLSA",
  "name": "_${PORT}._${PROTOCOL}.${domain}",
  "data": {
    "usage": $USAGE,
    "selector": $SELECTOR,
    "matching_type": $MATCHING_TYPE,
    "certificate": "$cert_hash"
  }
}
EOF
)

  curl -s -X PUT -H "Authorization: Bearer $api_token" -H "Content-Type: application/json" \
    -d "$payload" "$url"
}

# Function to delete all TLSA records
delete_all_records() {
  zone_id="$1"
  api_token="$2"
  tlsa_records="$3"

  for record_id in $(echo "$tlsa_records" | jq -r '.result[].id'); do
    log "Deleting TLSA record: $record_id"
    url="${API_URL}/${zone_id}/dns_records/$record_id"
    curl -s -X DELETE -H "Authorization: Bearer $api_token" "$url"
  done
}

# Main logic
log "Generating current certificate hash"
current_cert=$(generate_cert "$KEY_FILE")
log "Generated cert hash: $current_cert"

log "Generating next certificate hash"
next_cert=$(generate_cert "$KEY_FILE_NEXT")
log "Generated next cert hash: $next_cert"

log "Fetching TLSA records"
tlsa_records=$(get_tlsa_records "$ZONE_ID" "$API_TOKEN" "$DOMAIN")

# Check number of records and modify if necessary
record_count=$(echo "$tlsa_records" | jq '.result | length')

if [[ $record_count -ne 2 ]]; then
  log "Incorrect number of TLSA records, recreating all."
  delete_all_records "$ZONE_ID" "$API_TOKEN" "$tlsa_records"
  add_tlsa_record "$ZONE_ID" "$API_TOKEN" "$DOMAIN" "$next_cert"
  add_tlsa_record "$ZONE_ID" "$API_TOKEN" "$DOMAIN" "$current_cert"
else
  log "Checking for required updates."
  cert0=$(echo "$tlsa_records" | jq -r '.result[0].data.certificate')
  cert1=$(echo "$tlsa_records" | jq -r '.result[1].data.certificate')
  id0=$(echo "$tlsa_records" | jq -r '.result[0].id')
  id1=$(echo "$tlsa_records" | jq -r '.result[1].id')

  if [[ "$cert0" != "$current_cert" ]] && [[ "$cert1" != "$next_cert" ]]; then
    modify_tlsa_record "$ZONE_ID" "$API_TOKEN" "$DOMAIN" "$next_cert" "$id1"
    modify_tlsa_record "$ZONE_ID" "$API_TOKEN" "$DOMAIN" "$current_cert" "$id0"
  else
    log "No updates required."
  fi
fi

log "Process complete."
exit 0