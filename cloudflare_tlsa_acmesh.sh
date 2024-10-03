#!/bin/bash

# Ensure required environment variables are set
required_env_vars=("KEY_FILE" "KEY_FILE_NEXT" "CF_ZONE_ID" "CF_TOKEN" "DOMAIN")
for var in "${required_env_vars[@]}"; do
  if [[ -z "${!var}" ]]; then
    echo "Error: $var environment variable is not defined" >&2
    exit 1
  fi
done

# Set default port and protocol from environment variables, or use default values
PORT=${PORT:-25}
PROTOCOL=${PROTOCOL:-"tcp"}
CF_API="https://api.cloudflare.com/client/v4/zones"
USAGE=3
SELECTOR=1
MATCHING_TYPE=1

# Logging function
log() {
  echo "[$(date)] $1"
}

# Function to detect key type (RSA or EC) from PEM header and generate certificate hash
generate_cert() {
  key_file="$1"
  
  if [[ ! -f "$key_file" ]]; then
    echo "Error: Key file $key_file does not exist" >&2
    exit 1
  fi

  # Read the first line of the key file to check the PEM header
  pem_header=$(head -n 1 "$key_file")

  if [[ "$pem_header" == "-----BEGIN RSA PRIVATE KEY-----" ]]; then
    log "Detected RSA key type for $key_file"
    pub_key=$(openssl rsa -in "$key_file" -pubout 2>/dev/null)
  elif [[ "$pem_header" == "-----BEGIN EC PRIVATE KEY-----" ]]; then
    log "Detected EC key type for $key_file"
    pub_key=$(openssl ec -in "$key_file" -pubout 2>/dev/null)
  else
    echo "Error: Unsupported key type or unable to detect key type for $key_file" >&2
    exit 1
  fi

  if [[ $? -ne 0 ]]; then
    echo "Error: Failed to extract public key from $key_file" >&2
    exit 1
  fi

  # Hash the public key with SHA256
  cert_hash=$(echo "$pub_key" | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -binary | xxd -p -c 256)

  echo "$cert_hash"
}

# Function to get TLSA records
get_tlsa_records() {
  zone_id="$1"
  api_token="$2"
  domain="$3"
  
  log "Fetching TLSA records for domain: $domain"
  url="${CF_API}/${zone_id}/dns_records?name=_${PORT}._${PROTOCOL}.${domain}"

  # Capture both status code and response
  response=$(curl -s -w "\n%{http_code}" -X GET -H "Authorization: Bearer $api_token" "$url")
  http_code=$(echo "$response" | tail -n 1)
  response_body=$(echo "$response" | sed '$d')

  # Check HTTP status code
  if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
    echo "$response_body"
  else
    log "Failed to get TLSA records. HTTP status code: $http_code, response: $response_body" >&2
    exit 1
  fi
}

# Function to add TLSA record
add_tlsa_record() {
  zone_id="$1"
  api_token="$2"
  domain="$3"
  cert_hash="$4"

  log "Adding TLSA record with cert hash: $cert_hash"
  url="${CF_API}/${zone_id}/dns_records"
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

  response=$(curl -s -w "\n%{http_code}" -X POST -H "Authorization: Bearer $api_token" -H "Content-Type: application/json" \
    -d "$payload" "$url")
  http_code=$(echo "$response" | tail -n 1)
  response_body=$(echo "$response" | sed '$d')

  if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
    log "TLSA record added successfully."
  else
    log "Failed to add TLSA record. HTTP status code: $http_code, response: $response_body" >&2
    exit 1
  fi
}

# Function to modify existing TLSA record
modify_tlsa_record() {
  zone_id="$1"
  api_token="$2"
  domain="$3"
  cert_hash="$4"
  record_id="$5"

  log "Modifying TLSA record $record_id with cert hash: $cert_hash"
  url="${CF_API}/${zone_id}/dns_records/$record_id"
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

  response=$(curl -s -w "\n%{http_code}" -X PUT -H "Authorization: Bearer $api_token" -H "Content-Type: application/json" \
    -d "$payload" "$url")
  http_code=$(echo "$response" | tail -n 1)
  response_body=$(echo "$response" | sed '$d')

  if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
    log "TLSA record modified successfully."
  else
    log "Failed to modify TLSA record $record_id. HTTP status code: $http_code, response: $response_body" >&2
    exit 1
  fi
}

# Function to delete all TLSA records
delete_all_records() {
  zone_id="$1"
  api_token="$2"
  tlsa_records="$3"

  for record_id in $(echo "$tlsa_records" | jq -r '.result[].id'); do
    log "Deleting TLSA record: $record_id"
    url="${CF_API}/${zone_id}/dns_records/$record_id"
    response=$(curl -s -w "\n%{http_code}" -X DELETE -H "Authorization: Bearer $api_token" "$url")
    http_code=$(echo "$response" | tail -n 1)

    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
      log "TLSA record $record_id deleted successfully."
    else
      log "Failed to delete TLSA record $record_id. HTTP status code: $http_code" >&2
      exit 1
    fi
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
tlsa_records=$(get_tlsa_records "$CF_ZONE_ID" "$CF_TOKEN" "$DOMAIN")

# Check number of records and modify if necessary
record_count=$(echo "$tlsa_records" | jq '.result | length')

if [[ $record_count -ne 2 ]]; then
  log "Incorrect number of TLSA records, recreating all."
  delete_all_records "$CF_ZONE_ID" "$CF_TOKEN" "$tlsa_records"
  add_tlsa_record "$CF_ZONE_ID" "$CF_TOKEN" "$DOMAIN" "$next_cert"
  add_tlsa_record "$CF_ZONE_ID" "$CF_TOKEN" "$DOMAIN" "$current_cert"
else
  log "Checking for required updates."
  cert0=$(echo "$tlsa_records" | jq -r '.result[0].data.certificate')
  cert1=$(echo "$tlsa_records" | jq -r '.result[1].data.certificate')
  id0=$(echo "$tlsa_records" | jq -r '.result[0].id')
  id1=$(echo "$tlsa_records" | jq -r '.result[1].id')

  # Case 1: cert0 == current_cert && cert1 == next_cert (no change required)
  if [[ "$cert0" == "$current_cert" && "$cert1" == "$next_cert" ]]; then
    log "TLSA records are up-to-date. No changes required."
  
  # Case 2: cert0 == next_cert && cert1 == current_cert (no change required)
  elif [[ "$cert0" == "$next_cert" && "$cert1" == "$current_cert" ]]; then
    log "TLSA records are up-to-date but reversed. No changes required."
  
  # Case 3: cert0 == current_cert but cert1 is incorrect (modify cert1 to next_cert)
  elif [[ "$cert0" == "$current_cert" && "$cert1" != "$next_cert" ]]; then
    log "Updating TLSA record $id1 with next certificate."
    modify_tlsa_record "$CF_ZONE_ID" "$CF_TOKEN" "$DOMAIN" "$next_cert" "$id1"
  
  # Case 4: cert0 == next_cert but cert1 is incorrect (modify cert1 to current_cert)
  elif [[ "$cert0" == "$next_cert" && "$cert1" != "$current_cert" ]]; then
    log "Updating TLSA record $id1 with current certificate."
    modify_tlsa_record "$CF_ZONE_ID" "$CF_TOKEN" "$DOMAIN" "$current_cert" "$id1"

  # Case 5: cert1 == current_cert but cert0 is incorrect (modify cert0 to next_cert)
  elif [[ "$cert1" == "$current_cert" && "$cert0" != "$next_cert" ]]; then
    log "Updating TLSA record $id0 with next certificate."
    modify_tlsa_record "$CF_ZONE_ID" "$CF_TOKEN" "$DOMAIN" "$next_cert" "$id0"

  # Case 6: cert1 == next_cert but cert0 is incorrect (modify cert0 to current_cert)
  elif [[ "$cert1" == "$next_cert" && "$cert0" != "$current_cert" ]]; then
    log "Updating TLSA record $id0 with current certificate."
    modify_tlsa_record "$CF_ZONE_ID" "$CF_TOKEN" "$DOMAIN" "$current_cert" "$id0"

  # Case 7: Both certs are incorrect, modify both records
  else
    log "Neither TLSA records are correct. Updating both records."
    modify_tlsa_record "$CF_ZONE_ID" "$CF_TOKEN" "$DOMAIN" "$next_cert" "$id1"
    modify_tlsa_record "$CF_ZONE_ID" "$CF_TOKEN" "$DOMAIN" "$current_cert" "$id0"
  fi
fi

log "Process complete."
exit 0