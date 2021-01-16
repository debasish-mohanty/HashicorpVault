#!/bin/bash 
# shellcheck disable=SC2005,SC2030,SC2031,SC2174
#
# This script helps manage Vault running in a multi-node cluster
# using the integrated storage (Raft) backend.
#
# Learn Guide: https://learn.hashicorp.com/vault/beta/raft-storage
#
# NOTES:
# - This script is intended only to be used in an educational capacity.
# - This script is not intended to manage a Vault in a production environment.
# - This script supports Linux and macOS
# - Linux support expects the 'ip' command instead of 'ifcnfig' command

set -e

sudo mkdir -pm 0775 /opt/vault/{audit,bin,config,data,hsm,logs,plugin}
sudo chown -R vault:vault /opt/vault/
demo_home="/opt/vault"

vault_file=/opt/vault/bin/vault

if [ -f "$vault_file" ]; then
    echo "$vault_file exists."
else 
    echo "$vault_file does not exist, downloading it from hashicorp"
    wget -N https://releases.hashicorp.com/vault/1.6.1+ent.hsm/vault_1.6.1+ent.hsm_linux_amd64.zip 
    unzip vault_1.6.1+ent.hsm_linux_amd64.zip
    mv vault /opt/vault/bin/
fi

hsm_lib_file=/opt/vault/hsm/fortanix_pkcs11_3.23.1395.so

if [ -f "$hsm_lib_file" ]; then
    echo "HSM library file exist."
else
    echo "HSM library file does not exist, downloading it from Fortanix"
    wget -N https://s3-us-west-1.amazonaws.com/downloads.fortanix.com/3.23.1395/fortanix_pkcs11_3.23.1395.so    
    mv fortanix_pkcs11_3.23.1395.so /opt/vault/hsm/
    tee "$demo_home"/hsm/pkcs11.conf 1> /dev/null <<EOF

# Fortanix HSM Configuration

api_key = "YTY5OTQ1YTMtNGQzZS00Nzk5LWFlZGEtM2RmZDQwNWQ0M2IxOnJZd2Q3WTR6S0UxRnlVOGg2SlZHZ0tjd2ZBbEN6RTFXNzJIa0ltWVlBUlplU3d0OWR2dUhPblFNbVMweEtVSGlGYWVaeWRVYjNpcndtdk5LampjbDR3"
api_endpoint = "https://sdkms.fortanix.com"
fake_rsa_x9_31_keygen_support = false # default is false

#ca_certs_file = "/path/to/certs.pem" # X.509 PEM CA certificates

#cert_file = "/path/to/cert.pem" # X.509 PEM client certificate
#key_file = "/path/to/key.pem" # PKCS#8 PEM client private key
#app_id = "UUID OF APPLICATION"

prevent_duplicate_opaque_objects = true
retry_timeout_millis = 3000

[log]
system = true # Unix only, logs to syslog
#file = "/path/to/log/file"
EOF
fi


script_name="$(basename "$0")"
os_name="$(uname -s | awk '{print tolower($0)}')"

if [ "$os_name" != "darwin" ] && [ "$os_name" != "linux" ]; then
  >&2 echo "Sorry, this script supports only Linux or macOS operating systems."
  exit 1
fi

function vault_to_network_address {
  local vault_node_name=$1

  case "$vault_node_name" in
    vault_1)
      echo "http://127.0.0.1:8210"
      ;;
    vault_2)
      echo "http://127.0.0.1:8220"
      ;;
    vault_3)
      echo "http://127.0.0.1:8230"
      ;;
    vault_4)
      echo "http://127.0.0.1:8240"
      ;;
    vault_5)
      echo "http://127.0.0.1:8250"
      ;;
    vault_6)
      echo "http://127.0.0.1:8260"
      ;;
  esac
}

# Create a helper function to address the first vault node
function vault_1 {
    (export VAULT_ADDR=http://127.0.0.1:8210 && vault "$@")
}

# Create a helper function to address the second vault node
function vault_2 {
    (export VAULT_ADDR=http://127.0.0.1:8220 && vault "$@")
}

# Create a helper function to address the third vault node
function vault_3 {
    (export VAULT_ADDR=http://127.0.0.1:8230 && vault "$@")
}

# Create a helper function to address the fourth vault node
function vault_4 {
    (export VAULT_ADDR=http://127.0.0.1:8240 && vault "$@")
}

# Create a helper function to address the fifth vault node
function vault_5 {
    (export VAULT_ADDR=http://127.0.0.1:8250 && vault "$@")
}

# Create a helper function to address the sixth vault node
function vault_6 {
    (export VAULT_ADDR=http://127.0.0.1:8260 && vault "$@")
}

function stop_vault {
  local vault_node_name=$1

  service_count=$(pgrep -f "$demo_home"/config/config-"$vault_node_name" | wc -l | tr -d '[:space:]')

  printf "\n%s" \
    "Found $service_count Vault service(s) matching that name"

  if [ "$service_count" != "0" ] ; then
    printf "\n%s" \
      "[$vault_node_name] stopping" \
      ""

    pkill -f "$demo_home/config/$vault_node_name"
  fi
}

function stop {
  case "$1" in
    vault_1)
      stop_vault "vault_1"
      ;;
    vault_2)
      stop_vault "vault_2"
      ;;
    vault_3)
      stop_vault "vault_3"
      ;;
    vault_4)
      stop_vault "vault_4"
      ;;
    vault_5)
      stop_vault "vault_5"
      ;;
    vault_6)
      stop_vault "vault_6"
      ;;
    all)
      for vault_node_name in vault_1 vault_2 vault_3 vault_4 vault_5 vault_6 ; do
        stop_vault $vault_node_name
      done
      ;;
    *)
      printf "\n%s" \
        "Usage: $script_name stop [all|vault_1|vault_2|vault_3|vault_4|vault_5|vault_6]" \
        ""
      ;;
    esac
}


function clean {

  for config_file in $demo_home/config/config-vault_1.hcl $demo_home/config/config-vault_2.hcl $demo_home/config/config-vault_3.hcl $demo_home/config/config-vault_4.hcl $demo_home/config/config-vault_5.hcl $demo_home/config/config-vault_6.hcl ; do
    if [[ -f "$config_file" ]] ; then
      printf "\n%s" \
        "Removing configuration file $config_file"

      rm "$config_file"
      printf "\n"
    fi
  done

  for raft_storage in $demo_home/data/ha-raft_1 $demo_home/data/ha-raft_2 $demo_home/data/ha-raft_3 $demo_home/data/ha-raft_4 $demo_home/data/ha-raft_5 $demo_home/data/ha-raft_6 $demo_home/data/vault-storage-file ; do
    if [[ -d "$raft_storage" ]] ; then
    printf "\n%s" \
        "Removing raft storage file $raft_storage"

      rm -rf "$raft_storage"
    fi
  done

  for key_file in $demo_home/rootToken1 $demo_home/rootToken2 $demo_home/unsealKey1 $demo_home/unsealKey2 $demo_home/recoveryKey1 $demo_home/recoveryKey2 ; do
    if [[ -f "$key_file" ]] ; then
      printf "\n%s" \
        "Removing key $key_file"

      rm "$key_file"
    fi
  done

  for token_file in $demo_home/root_token-vault_1 $demo_home/root_token-vault_4 ; do
    if [[ -f "$token_file" ]] ; then
      printf "\n%s" \
        "Removing key $token_file"

      rm "$token_file"
    fi
  done

  for vault_log in $demo_home/logs/vault_1.log $demo_home/logs/vault_2.log $demo_home/logs/vault_3.log $demo_home/logs/vault_4.log $demo_home/logs/vault_5.log $demo_home/logs/vault_6.log ; do
    if [[ -f "$vault_log" ]] ; then
      printf "\n%s" \
        "Removing log file $vault_log"

      rm "$vault_log"
    fi
  done

  # to successfully demo again later, previous VAULT_TOKEN cannot be present
  unset VAULT_TOKEN

  printf "\n%s" \
    "Clean complete" \
    ""
}

function status {
  service_count=$(pgrep -f "$demo_home"/config/config | wc -l | tr -d '[:space:]')

  printf "\n%s" \
    "Found $service_count Vault services" \
    ""

  if [[ "$service_count" != 6 ]] ; then
    printf "\n%s" \
    "Unable to find all Vault services" \
    ""
  fi

  printf "\n%s" \
    "[vault_1] status" \
    ""
  vault_1 status || true

  printf "\n%s" \
    "[vault_2] status" \
    ""
  vault_2 status || true

  printf "\n%s" \
    "[vault_3] status" \
    ""
  vault_3 status || true

  printf "\n%s" \
    "[vault_4] status" \
    ""
  vault_4 status || true

  printf "\n%s" \
    "[vault_5] status" \
    ""
  vault_5 status || true

  printf "\n%s" \
    "[vault_6] status" \
    ""
  vault_6: status || true

  sleep 2
}


function create_config {
  rm -rf "$demo_home"/data/vault-storage-file
  mkdir -pm 0755 "$demo_home"/data/vault-storage-file

  printf "\n%s" \
    "[vault_1] Creating configuration" \
    "  - creating $demo_home/config/config-vault_1.hcl" \
    "  - creating $demo_home/data/ha-raft_1"

  rm -f "$demo_home"/config/config-vault_1.hcl
  rm -rf "$demo_home"/data/ha-raft_1
  mkdir -pm 0755 "$demo_home"/data/ha-raft_1

  tee "$demo_home"/config/config-vault_1.hcl 1> /dev/null <<EOF
#General parameters

cluster_name = "DR_PRIMARY"
api_addr = "http://127.0.0.1:8210"
cluster_addr = "http://127.0.0.1:8211"
log_level = "Info"
ui = true
Plugin_directory = "/opt/vault/plugin"
disable_mlock=true

#Listener Parameters

listener "tcp" {
    address          = "0.0.0.0:8210"
    cluster_address  = "0.0.0.0:8211"
    #tls_cert_file = "/opt/vault/config/certs/vault-dev.sc.net_cert.cer"
    #tls_key_file = "/opt/vault/config/certs/vault-dev.sc.net-private.key"
    #tls_min_version = "tls12"
    #tls_disable_client_certs= "true"
    tls_disable = true
}

#HSM Parameters

seal "pkcs11" {
  lib = "/opt/vault/hsm/fortanix_pkcs11_3.23.1395.so"
  slot = "0"
  pin = "file:///opt/vault/hsm/pkcs11.conf"
  key_label = "HASHICORP-VAULT"
  hmac_key_label = "HMAC-HSM-NonProd-KEY"
  generate_key = "true"
}

#Storage Backend

storage "raft" {
  path    = "$demo_home/data/ha-raft_1/"
  node_id = "vault_1"
  retry_join {
  leader_api_addr = "http://127.0.0.1:8220"
  }
  retry_join {
  leader_api_addr = "http://127.0.0.1:8230"
  }
}

#Monitoring Parameter

telemetry {
  dogstatsd_addr = "localhost:8110"
  enable_hostname_label = true
  prometheus_retention_time = "0h"
}
EOF

  printf "\n%s" \
    "[vault_2] Creating configuration" \
    "  - creating $demo_home/config/config-vault_2.hcl" \
    "  - creating $demo_home/data/ha-raft_2"

  rm -f "$demo_home"/config/config-vault_2.hcl
  rm -rf "$demo_home"/data/ha-raft_2
  mkdir -pm 0755 "$demo_home"/data/ha-raft_2

  tee "$demo_home"/config/config-vault_2.hcl 1> /dev/null <<EOF
#General parameters

cluster_name = "DR_PRIMARY"
api_addr = "http://127.0.0.1:8220"
cluster_addr = "http://127.0.0.1:8221"
log_level = "Info"
ui = true
Plugin_directory = "/opt/vault/plugin"
disable_mlock=true

#Listener Parameters

listener "tcp" {
    address          = "0.0.0.0:8220"
    cluster_address  = "0.0.0.0:8221"
    #tls_cert_file = "/opt/vault/config/certs/vault-dev.sc.net_cert.cer"
    #tls_key_file = "/opt/vault/config/certs/vault-dev.sc.net-private.key"
    #tls_min_version = "tls12"
    #tls_disable_client_certs= "true"
    tls_disable = true
}

#HSM Parameters

seal "pkcs11" {
  lib = "/opt/vault/hsm/fortanix_pkcs11_3.23.1395.so"
  slot = "0"
  pin = "file:///opt/vault/hsm/pkcs11.conf"
  key_label = "HASHICORP-VAULT"
  hmac_key_label = "HMAC-HSM-NonProd-KEY"
  generate_key = "true"
}

#Storage Backend

storage "raft" {
  path    = "$demo_home/data/ha-raft_2/"
  node_id = "vault_2"
  retry_join {
  leader_api_addr = "http://127.0.0.1:8210"
  }
  retry_join {
  leader_api_addr = "http://127.0.0.1:8230"
  }
}

#Monitoring Parameter

telemetry {
  dogstatsd_addr = "localhost:8120"
  enable_hostname_label = true
  prometheus_retention_time = "0h"
}
EOF

  printf "\n%s" \
    "[vault_3] Creating configuration" \
    "  - creating $demo_home/config-vault_3.hcl" \
    "  - creating $demo_home/ha-raft_3"

  rm -f "$demo_home"/config/config-vault_3.hcl
  rm -rf "$demo_home"/data/ha-raft_3
  mkdir -pm 0755 "$demo_home"/data/ha-raft_3

  tee "$demo_home"/config/config-vault_3.hcl 1> /dev/null <<EOF
  #General parameters

cluster_name = "DR_PRIMARY"
api_addr = "http://127.0.0.1:8230"
cluster_addr = "http://127.0.0.1:8231"
log_level = "Info"
ui = true
Plugin_directory = "/opt/vault/plugin"
disable_mlock=true

#Listener Parameters

listener "tcp" {
    address          = "0.0.0.0:8230"
    cluster_address  = "0.0.0.0:8231"
    #tls_cert_file = "/opt/vault/config/certs/vault-dev.sc.net_cert.cer"
    #tls_key_file = "/opt/vault/config/certs/vault-dev.sc.net-private.key"
    #tls_min_version = "tls12"
    #tls_disable_client_certs= "true"
    tls_disable = true
}

#HSM Parameters

seal "pkcs11" {
  lib = "/opt/vault/hsm/fortanix_pkcs11_3.23.1395.so"
  slot = "0"
  pin = "file:///opt/vault/hsm/pkcs11.conf"
  key_label = "HASHICORP-VAULT"
  hmac_key_label = "HMAC-HSM-NonProd-KEY"
  generate_key = "true"
}

#Storage Backend

storage "raft" {
  path    = "$demo_home/data/ha-raft_3/"
  node_id = "vault_3"
  retry_join {
  leader_api_addr = "http://127.0.0.1:8210"
  }
  retry_join {
  leader_api_addr = "http://127.0.0.1:8220"
  }
}

#Monitoring Parameter

telemetry {
  dogstatsd_addr = "localhost:8130"
  enable_hostname_label = true
  prometheus_retention_time = "0h"
}
EOF
printf "\n%s" \
    "[vault_4] Creating configuration" \
    "  - creating $demo_home/config/config-vault_4.hcl" \
    "  - creating $demo_home/data/ha-raft_4"

  rm -f "$demo_home"/config/config-vault_4.hcl
  rm -rf "$demo_home"/data/ha-raft_4
  mkdir -pm 0755 "$demo_home"/data/ha-raft_4

  tee "$demo_home"/config/config-vault_4.hcl 1> /dev/null <<EOF
#General parameters

cluster_name = "DR_SECONDARY"
api_addr = "http://127.0.0.1:8240"
cluster_addr = "http://127.0.0.1:8241"
log_level = "Info"
ui = true
Plugin_directory = "/opt/vault/plugin"
disable_mlock=true

#Listener Parameters

listener "tcp" {
    address          = "0.0.0.0:8240"
    cluster_address  = "0.0.0.0:8241"
    #tls_cert_file = "/opt/vault/config/certs/vault-dev.sc.net_cert.cer"
    #tls_key_file = "/opt/vault/config/certs/vault-dev.sc.net-private.key"
    #tls_min_version = "tls12"
    #tls_disable_client_certs= "true"
    tls_disable = true
}

#HSM Parameters

seal "pkcs11" {
  lib = "/opt/vault/hsm/fortanix_pkcs11_3.23.1395.so"
  slot = "0"
  pin = "file:///opt/vault/hsm/pkcs11.conf"
  key_label = "HASHICORP-VAULT"
  hmac_key_label = "HMAC-HSM-NonProd-KEY"
  generate_key = "true"
}

#Storage Backend

storage "raft" {
  path    = "$demo_home/data/ha-raft_4/"
  node_id = "vault_4"
  retry_join {
  leader_api_addr = "http://127.0.0.1:8250"
  }
  retry_join {
  leader_api_addr = "http://127.0.0.1:8260"
  }
}

#Monitoring Parameter

telemetry {
  dogstatsd_addr = "localhost:8140"
  enable_hostname_label = true
  prometheus_retention_time = "0h"
}
EOF

  printf "\n%s" \
    "[vault_5] Creating configuration" \
    "  - creating $demo_home/config/config-vault_5.hcl" \
    "  - creating $demo_home/data/ha-raft_5"

  rm -f "$demo_home"/config/config-vault_5.hcl
  rm -rf "$demo_home"/data/ha-raft_5
  mkdir -pm 0755 "$demo_home"/data/ha-raft_5

  tee "$demo_home"/config/config-vault_5.hcl 1> /dev/null <<EOF
#General parameters

cluster_name = "DR_SECONDARY"
api_addr = "http://127.0.0.1:8250"
cluster_addr = "http://127.0.0.1:8251"
log_level = "Info"
ui = true
Plugin_directory = "/opt/vault/plugin"
disable_mlock=true

#Listener Parameters

listener "tcp" {
    address          = "0.0.0.0:8250"
    cluster_address  = "0.0.0.0:8251"
    #tls_cert_file = "/opt/vault/config/certs/vault-dev.sc.net_cert.cer"
    #tls_key_file = "/opt/vault/config/certs/vault-dev.sc.net-private.key"
    #tls_min_version = "tls12"
    #tls_disable_client_certs= "true"
    tls_disable = true
}

#HSM Parameters

seal "pkcs11" {
  lib = "/opt/vault/hsm/fortanix_pkcs11_3.23.1395.so"
  slot = "0"
  pin = "file:///opt/vault/hsm/pkcs11.conf"
  key_label = "HASHICORP-VAULT"
  hmac_key_label = "HMAC-HSM-NonProd-KEY"
  generate_key = "true"
}

#Storage Backend

storage "raft" {
  path    = "$demo_home/data/ha-raft_5/"
  node_id = "vault_5"
  retry_join {
  leader_api_addr = "http://127.0.0.1:8240"
  }
  retry_join {
  leader_api_addr = "http://127.0.0.1:8260"
  }
}

#Monitoring Parameter

telemetry {
  dogstatsd_addr = "localhost:8150"
  enable_hostname_label = true
  prometheus_retention_time = "0h"
}
EOF

  printf "\n%s" \
    "[vault_6] Creating configuration" \
    "  - creating $demo_home/config-vault_6.hcl" \
    "  - creating $demo_home/ha-raft_6"

  rm -f "$demo_home"/config/config-vault_6.hcl
  rm -rf "$demo_home"/data/ha-raft_6
  mkdir -pm 0755 "$demo_home"/data/ha-raft_6

  tee "$demo_home"/config/config-vault_6.hcl 1> /dev/null <<EOF
  #General parameters

cluster_name = "DR_SECONDARY"
api_addr = "http://127.0.0.1:8260"
cluster_addr = "http://127.0.0.1:8261"
log_level = "Info"
ui = true
Plugin_directory = "/opt/vault/plugin"
disable_mlock=true

#Listener Parameters

listener "tcp" {
    address          = "0.0.0.0:8260"
    cluster_address  = "0.0.0.0:8261"
    #tls_cert_file = "/opt/vault/config/certs/vault-dev.sc.net_cert.cer"
    #tls_key_file = "/opt/vault/config/certs/vault-dev.sc.net-private.key"
    #tls_min_version = "tls12"
    #tls_disable_client_certs= "true"
    tls_disable = true
}

#HSM Parameters

seal "pkcs11" {
  lib = "/opt/vault/hsm/fortanix_pkcs11_3.23.1395.so"
  slot = "0"
  pin = "file:///opt/vault/hsm/pkcs11.conf"
  key_label = "HASHICORP-VAULT"
  hmac_key_label = "HMAC-HSM-NonProd-KEY"
  generate_key = "true"
}

#Storage Backend

storage "raft" {
  path    = "$demo_home/data/ha-raft_6/"
  node_id = "vault_6"
  retry_join {
  leader_api_addr = "http://127.0.0.1:8240"
  }
  retry_join {
  leader_api_addr = "http://127.0.0.1:8250"
  }
}

#Monitoring Parameter

telemetry {
  dogstatsd_addr = "localhost:8160"
  enable_hostname_label = true
  prometheus_retention_time = "0h"
}
EOF
  printf "\n"
}

function setup_vault_1 {

  set -aex
  # Kill all previous server instances
  for pid in $(ps aux | grep "vault server" | grep -v grep | awk '{print $2}'); do
      kill ${pid}
  done

  local vault_node_name="vault_1"
  local vault_config_file=$demo_home/config/config-$vault_node_name.hcl
  local vault_log_file=$demo_home/logs/$vault_node_name.log

  printf "\n%s" \
    "[$vault_node_name] starting Vault server @ $vault_node_name" \
    ""

  VAULT_API_ADDR=http://127.0.0.1:8210 vault server -log-level=trace -config "$vault_config_file" > "$vault_log_file" 2>&1 &
  while ! nc -w 1 localhost 8210 </dev/null; do sleep 1; done

  printf "\n%s" \
    "[vault_1] initializing and capturing the recovery key and root token" \
    ""

  # Initialize the second node and capture its recovery keys and root token
  initResult=$(vault_1 operator init -format=json -recovery-shares=1 -recovery-threshold=1)

  recoveryKey1=$(echo -n $initResult | jq -r '.recovery_keys_b64[0]')
  rootToken1=$(echo -n $initResult | jq -r '.root_token')
  echo -n $recoveryKey1 > $demo_home/recoveryKey1
  echo -n $rootToken1 > $demo_home/rootToken1

  #vault_1 operator unseal `cat $demo_home/unsealKey1`

  sleep 10s

  vault_1 login `cat $demo_home/rootToken1`

  printf "\n%s" \
    "[vault_1] waiting to finish post-unseal setup (15 seconds)" \
    ""

  sleep 5s

  printf "\n%s" \
    "[vault_1] Installing License" \
    ""
  vault_1 write sys/license text="02MV4UU43BK5HGYYTOJZWFQMTMNNEWU33JJZ5GGM2PIRWG2TSXKV2E6RCCNFMWSMBTJZLU42KMKRGTCWLNIV2FU3KVGNMVOSTLJVDVC6C2IREXUSLJO5UVSM2WPJSEOOLULJMEUZTBK5IWST3JJEZVUR2SNFMWUQTMLFUTANCNKRDGQTCUJF5E4VCVORHFOTTKLF4TC222I5MXOTSEKV5FSVDENBNGUZ3JJRBUU4DCNZHDAWKXPBZVSWCSOBRDENLGMFLVC2KPNFEXCSLJO5UWCWCOPJSFOVTGMRDWY5C2KNETMSLKJF3U22SBORGUIZ3UJVKEMVKNKRITMTSEIU3E22TLOVGXUQJRJZCE26COKRCTIV3JJFZUS3SOGBMVQSRQLAZVE4DCK5KWST3JJF4U2RCJO5GFIQJUJRKEK6CWIRAXOT3KIF3U62SBO5LWSSLTJFWVMNDDI5WHSWKYKJYGEMRVMZSEO3DULJJUSNSJNJEXOTLKIV2E2RDHORGVIRSVJVVE2NSOKRVTMTSUNN2U6VDLGVLWSSLTJFXFE3DDNUYXAYTNIYYGCVZZOVMDGUTQMJLVK2KPNFEXSTKEJF4EYVCBGVGFIRJRKZCEC52PNJAXOT3KIF3VO2KJONEW4QTZMIZFEMKZGNIWST3JJIZFSWCWONSEGSLTJFWVU42ZK5SHUSLKOA3US3JROZNEQVTTLJME22KPNRZWSYSYKZZWIR3LORNEOTLUMMZE42DCI5KWSTCDJJXGEM22NRRW2NLIMJWU43CMLBBHMYSHNRVGKU2JONEW2RTLMRWUM5KZGJLGWTCXKJUGIR2FORRUQSTWMRDVM2TEI5WHMYTJJJSGMWBQHUXGGYLLOJYXO23DFNXUCOBVLF5FMN2NGF4DGUTMF5XDEYJLJJLW2M2SOB5GI5JXGQ3WCMKFKRRSW6CMHAXWU2LVMVVGIUSUPBTXASJQKVAVETSZOVRUSQLMIN5EO2LHO5QWYYZZHFBVUMLEIFVWGYJUMRLDAMZTHBIHO3KWNRQXMSSQGRYEU6CJJE4UINSVIZGFKYKWKBVGWV2KORRUINTQMFWDM32PMZDW4SZSPJIEWSSSNVDUQVRTMVNHO4KGMUVW6N3LF5ZSWQKUJZUFAWTHKMXUWVSZM4XUWK3MI5IHOTBXNJBHQSJXI5HWC2ZWKVQWSYKIN5SWWMCSKRXTOMSEKE6T2"

  sleep 2s

  printf "\n%s" \
    "[vault_1] logging in and enabling the KV secrets engine" \
    ""
  sleep 2s # Added for human readability

  vault_1 secrets enable -path=kv kv-v2
  sleep 2s

  printf "\n%s" \
    "[vault_1] storing secret 'kv/apikey' for testing" \
    ""

  vault_1 kv put kv/apikey webapp=ABB39KKPTWOR832JGNLS02
  vault_1 kv get kv/apikey
}

function setup_vault_2 {
  set -aex
  local vault_node_name="vault_2"
  local vault_config_file=$demo_home/config/config-$vault_node_name.hcl
  local vault_log_file=$demo_home/logs/$vault_node_name.log

  printf "\n%s" \
    "[$vault_node_name] starting Vault server @ $vault_node_name" \
    ""

  VAULT_API_ADDR=http://127.0.0.1:8220 vault server -log-level=trace -config "$vault_config_file" > "$vault_log_file" 2>&1 &
  while ! nc -w 1 localhost 8220 </dev/null; do sleep 1; done
  sleep 2s

  #printf "\n%s" \
   # "[$vault_node_name] Unseal $vault_node_name" \
   # ""
  #vault_2 operator unseal `cat $demo_home/unsealKey1`

  sleep 1s

  printf "\n%s" \
    "[$vault_node_name] Join the raft cluster" \
    ""
  #vault_2 operator raft join

  sleep 15s

  vault_2 login `cat $demo_home/rootToken1`

  printf "\n%s" \
    "[vault_1] Installing License" \
    ""
  vault_2 write sys/license text="02MV4UU43BK5HGYYTOJZWFQMTMNNEWU33JJZ5GGM2PIRWG2TSXKV2E6RCCNFMWSMBTJZLU42KMKRGTCWLNIV2FU3KVGNMVOSTLJVDVC6C2IREXUSLJO5UVSM2WPJSEOOLULJMEUZTBK5IWST3JJEZVUR2SNFMWUQTMLFUTANCNKRDGQTCUJF5E4VCVORHFOTTKLF4TC222I5MXOTSEKV5FSVDENBNGUZ3JJRBUU4DCNZHDAWKXPBZVSWCSOBRDENLGMFLVC2KPNFEXCSLJO5UWCWCOPJSFOVTGMRDWY5C2KNETMSLKJF3U22SBORGUIZ3UJVKEMVKNKRITMTSEIU3E22TLOVGXUQJRJZCE26COKRCTIV3JJFZUS3SOGBMVQSRQLAZVE4DCK5KWST3JJF4U2RCJO5GFIQJUJRKEK6CWIRAXOT3KIF3U62SBO5LWSSLTJFWVMNDDI5WHSWKYKJYGEMRVMZSEO3DULJJUSNSJNJEXOTLKIV2E2RDHORGVIRSVJVVE2NSOKRVTMTSUNN2U6VDLGVLWSSLTJFXFE3DDNUYXAYTNIYYGCVZZOVMDGUTQMJLVK2KPNFEXSTKEJF4EYVCBGVGFIRJRKZCEC52PNJAXOT3KIF3VO2KJONEW4QTZMIZFEMKZGNIWST3JJIZFSWCWONSEGSLTJFWVU42ZK5SHUSLKOA3US3JROZNEQVTTLJME22KPNRZWSYSYKZZWIR3LORNEOTLUMMZE42DCI5KWSTCDJJXGEM22NRRW2NLIMJWU43CMLBBHMYSHNRVGKU2JONEW2RTLMRWUM5KZGJLGWTCXKJUGIR2FORRUQSTWMRDVM2TEI5WHMYTJJJSGMWBQHUXGGYLLOJYXO23DFNXUCOBVLF5FMN2NGF4DGUTMF5XDEYJLJJLW2M2SOB5GI5JXGQ3WCMKFKRRSW6CMHAXWU2LVMVVGIUSUPBTXASJQKVAVETSZOVRUSQLMIN5EO2LHO5QWYYZZHFBVUMLEIFVWGYJUMRLDAMZTHBIHO3KWNRQXMSSQGRYEU6CJJE4UINSVIZGFKYKWKBVGWV2KORRUINTQMFWDM32PMZDW4SZSPJIEWSSSNVDUQVRTMVNHO4KGMUVW6N3LF5ZSWQKUJZUFAWTHKMXUWVSZM4XUWK3MI5IHOTBXNJBHQSJXI5HWC2ZWKVQWSYKIN5SWWMCSKRXTOMSEKE6T2"

  sleep 2s

  
  printf "\n%s" \
    "[$vault_node_name] List the raft cluster members" \
    ""
  vault_2 operator raft list-peers

  printf "\n%s" \
    "[$vault_node_name] Vault status" \
    ""
  vault_2 status
}

function setup_vault_3 {
  set -aex

  local vault_node_name="vault_3"
  local vault_config_file=$demo_home/config/config-$vault_node_name.hcl
  local vault_log_file=$demo_home/logs/$vault_node_name.log

  printf "\n%s" \
    "[$vault_node_name] starting Vault server @ $vault_node_name" \
    ""

  VAULT_API_ADDR=http://127.0.0.1:8230 vault server -log-level=trace -config "$vault_config_file" > "$vault_log_file" 2>&1 &
  while ! nc -w 1 localhost 8230 </dev/null; do sleep 1; done
  sleep 2s

  #printf "\n%s" \
  #  "[$vault_node_name] Unseal $vault_node_name" \
  #  ""
  #vault_3 operator unseal `cat $demo_home/unsealKey1`

  sleep 1s

  printf "\n%s" \
    "[$vault_node_name] Join the raft cluster" \
    ""
  #vault_3 operator raft join

  sleep 15s

  vault_3 login `cat $demo_home/rootToken1`

  printf "\n%s" \
    "[vault_1] Installing License" \
    ""
  vault_3 write sys/license text="02MV4UU43BK5HGYYTOJZWFQMTMNNEWU33JJZ5GGM2PIRWG2TSXKV2E6RCCNFMWSMBTJZLU42KMKRGTCWLNIV2FU3KVGNMVOSTLJVDVC6C2IREXUSLJO5UVSM2WPJSEOOLULJMEUZTBK5IWST3JJEZVUR2SNFMWUQTMLFUTANCNKRDGQTCUJF5E4VCVORHFOTTKLF4TC222I5MXOTSEKV5FSVDENBNGUZ3JJRBUU4DCNZHDAWKXPBZVSWCSOBRDENLGMFLVC2KPNFEXCSLJO5UWCWCOPJSFOVTGMRDWY5C2KNETMSLKJF3U22SBORGUIZ3UJVKEMVKNKRITMTSEIU3E22TLOVGXUQJRJZCE26COKRCTIV3JJFZUS3SOGBMVQSRQLAZVE4DCK5KWST3JJF4U2RCJO5GFIQJUJRKEK6CWIRAXOT3KIF3U62SBO5LWSSLTJFWVMNDDI5WHSWKYKJYGEMRVMZSEO3DULJJUSNSJNJEXOTLKIV2E2RDHORGVIRSVJVVE2NSOKRVTMTSUNN2U6VDLGVLWSSLTJFXFE3DDNUYXAYTNIYYGCVZZOVMDGUTQMJLVK2KPNFEXSTKEJF4EYVCBGVGFIRJRKZCEC52PNJAXOT3KIF3VO2KJONEW4QTZMIZFEMKZGNIWST3JJIZFSWCWONSEGSLTJFWVU42ZK5SHUSLKOA3US3JROZNEQVTTLJME22KPNRZWSYSYKZZWIR3LORNEOTLUMMZE42DCI5KWSTCDJJXGEM22NRRW2NLIMJWU43CMLBBHMYSHNRVGKU2JONEW2RTLMRWUM5KZGJLGWTCXKJUGIR2FORRUQSTWMRDVM2TEI5WHMYTJJJSGMWBQHUXGGYLLOJYXO23DFNXUCOBVLF5FMN2NGF4DGUTMF5XDEYJLJJLW2M2SOB5GI5JXGQ3WCMKFKRRSW6CMHAXWU2LVMVVGIUSUPBTXASJQKVAVETSZOVRUSQLMIN5EO2LHO5QWYYZZHFBVUMLEIFVWGYJUMRLDAMZTHBIHO3KWNRQXMSSQGRYEU6CJJE4UINSVIZGFKYKWKBVGWV2KORRUINTQMFWDM32PMZDW4SZSPJIEWSSSNVDUQVRTMVNHO4KGMUVW6N3LF5ZSWQKUJZUFAWTHKMXUWVSZM4XUWK3MI5IHOTBXNJBHQSJXI5HWC2ZWKVQWSYKIN5SWWMCSKRXTOMSEKE6T2"

  sleep 2s

  
  printf "\n%s" \
    "[$vault_node_name] List the raft cluster members" \
    ""
  vault_3 operator raft list-peers

  printf "\n%s" \
    "[$vault_node_name] Vault status" \
    ""
  vault_3 status
}
function setup_vault_4 {

  set -aex
  
  local vault_node_name="vault_4"
  local vault_config_file=$demo_home/config/config-$vault_node_name.hcl
  local vault_log_file=$demo_home/logs/$vault_node_name.log

  printf "\n%s" \
    "[$vault_node_name] starting Vault server @ $vault_node_name" \
    ""

  VAULT_API_ADDR=http://127.0.0.1:8240 vault server -log-level=trace -config "$vault_config_file" > "$vault_log_file" 2>&1 &
  while ! nc -w 1 localhost 8240 </dev/null; do sleep 1; done

  printf "\n%s" \
    "[vault_4] initializing and capturing the recovery key and root token" \
    ""

  # Initialize the forth node and capture its recovery keys and root token
  initResult=$(vault_4 operator init -format=json -recovery-shares=1 -recovery-threshold=1)

  recoveryKey2=$(echo -n $initResult | jq -r '.recovery_keys_b64[0]')
  rootToken2=$(echo -n $initResult | jq -r '.root_token')
  echo -n $recoveryKey2 > $demo_home/recoveryKey2
  echo -n $rootToken2 > $demo_home/rootToken2

  #vault_4 operator unseal `cat $demo_home/unsealKey2`

  sleep 10s

  vault_4 login `cat $demo_home/rootToken2`

  printf "\n%s" \
    "[vault_4] waiting to finish post-unseal setup (15 seconds)" \
    ""

  sleep 5s

  printf "\n%s" \
    "[vault_4] Installing License" \
    ""
  vault_4 write sys/license text="02MV4UU43BK5HGYYTOJZWFQMTMNNEWU33JJZ5GGM2PIRWG2TSXKV2E6RCCNFMWSMBTJZLU42KMKRGTCWLNIV2FU3KVGNMVOSTLJVDVC6C2IREXUSLJO5UVSM2WPJSEOOLULJMEUZTBK5IWST3JJEZVUR2SNFMWUQTMLFUTANCNKRDGQTCUJF5E4VCVORHFOTTKLF4TC222I5MXOTSEKV5FSVDENBNGUZ3JJRBUU4DCNZHDAWKXPBZVSWCSOBRDENLGMFLVC2KPNFEXCSLJO5UWCWCOPJSFOVTGMRDWY5C2KNETMSLKJF3U22SBORGUIZ3UJVKEMVKNKRITMTSEIU3E22TLOVGXUQJRJZCE26COKRCTIV3JJFZUS3SOGBMVQSRQLAZVE4DCK5KWST3JJF4U2RCJO5GFIQJUJRKEK6CWIRAXOT3KIF3U62SBO5LWSSLTJFWVMNDDI5WHSWKYKJYGEMRVMZSEO3DULJJUSNSJNJEXOTLKIV2E2RDHORGVIRSVJVVE2NSOKRVTMTSUNN2U6VDLGVLWSSLTJFXFE3DDNUYXAYTNIYYGCVZZOVMDGUTQMJLVK2KPNFEXSTKEJF4EYVCBGVGFIRJRKZCEC52PNJAXOT3KIF3VO2KJONEW4QTZMIZFEMKZGNIWST3JJIZFSWCWONSEGSLTJFWVU42ZK5SHUSLKOA3US3JROZNEQVTTLJME22KPNRZWSYSYKZZWIR3LORNEOTLUMMZE42DCI5KWSTCDJJXGEM22NRRW2NLIMJWU43CMLBBHMYSHNRVGKU2JONEW2RTLMRWUM5KZGJLGWTCXKJUGIR2FORRUQSTWMRDVM2TEI5WHMYTJJJSGMWBQHUXGGYLLOJYXO23DFNXUCOBVLF5FMN2NGF4DGUTMF5XDEYJLJJLW2M2SOB5GI5JXGQ3WCMKFKRRSW6CMHAXWU2LVMVVGIUSUPBTXASJQKVAVETSZOVRUSQLMIN5EO2LHO5QWYYZZHFBVUMLEIFVWGYJUMRLDAMZTHBIHO3KWNRQXMSSQGRYEU6CJJE4UINSVIZGFKYKWKBVGWV2KORRUINTQMFWDM32PMZDW4SZSPJIEWSSSNVDUQVRTMVNHO4KGMUVW6N3LF5ZSWQKUJZUFAWTHKMXUWVSZM4XUWK3MI5IHOTBXNJBHQSJXI5HWC2ZWKVQWSYKIN5SWWMCSKRXTOMSEKE6T2"

  sleep 2s

  printf "\n%s" \
    "[vault_4] logging in and enabling the KV secrets engine" \
    ""
  sleep 2s # Added for human readability

  vault_4 secrets enable -path=kv kv-v2
  sleep 2s

  printf "\n%s" \
    "[vault_4] storing secret 'kv/apikey' for testing" \
    ""

  vault_4 kv put kv/apikey webapp2=ABB39KKPTWOR832JGNLS02
  vault_4 kv get kv/apikey
}

function setup_vault_5 {
  set -aex
  local vault_node_name="vault_5"
  local vault_config_file=$demo_home/config/config-$vault_node_name.hcl
  local vault_log_file=$demo_home/logs/$vault_node_name.log

  printf "\n%s" \
    "[$vault_node_name] starting Vault server @ $vault_node_name" \
    ""

  VAULT_API_ADDR=http://127.0.0.1:8250 vault server -log-level=trace -config "$vault_config_file" > "$vault_log_file" 2>&1 &
  while ! nc -w 1 localhost 8250 </dev/null; do sleep 1; done
  sleep 2s

  #printf "\n%s" \
   # "[$vault_node_name] Unseal $vault_node_name" \
    #""
  #vault_5 operator unseal `cat $demo_home/unsealKey2`

  sleep 1s

  printf "\n%s" \
    "[$vault_node_name] Join the raft cluster" \
    ""
  #vault_5 operator raft join

  sleep 15s

  vault_5 login `cat $demo_home/rootToken2`

  printf "\n%s" \
    "[vault_5] Installing License" \
    ""
  vault_5 write sys/license text="02MV4UU43BK5HGYYTOJZWFQMTMNNEWU33JJZ5GGM2PIRWG2TSXKV2E6RCCNFMWSMBTJZLU42KMKRGTCWLNIV2FU3KVGNMVOSTLJVDVC6C2IREXUSLJO5UVSM2WPJSEOOLULJMEUZTBK5IWST3JJEZVUR2SNFMWUQTMLFUTANCNKRDGQTCUJF5E4VCVORHFOTTKLF4TC222I5MXOTSEKV5FSVDENBNGUZ3JJRBUU4DCNZHDAWKXPBZVSWCSOBRDENLGMFLVC2KPNFEXCSLJO5UWCWCOPJSFOVTGMRDWY5C2KNETMSLKJF3U22SBORGUIZ3UJVKEMVKNKRITMTSEIU3E22TLOVGXUQJRJZCE26COKRCTIV3JJFZUS3SOGBMVQSRQLAZVE4DCK5KWST3JJF4U2RCJO5GFIQJUJRKEK6CWIRAXOT3KIF3U62SBO5LWSSLTJFWVMNDDI5WHSWKYKJYGEMRVMZSEO3DULJJUSNSJNJEXOTLKIV2E2RDHORGVIRSVJVVE2NSOKRVTMTSUNN2U6VDLGVLWSSLTJFXFE3DDNUYXAYTNIYYGCVZZOVMDGUTQMJLVK2KPNFEXSTKEJF4EYVCBGVGFIRJRKZCEC52PNJAXOT3KIF3VO2KJONEW4QTZMIZFEMKZGNIWST3JJIZFSWCWONSEGSLTJFWVU42ZK5SHUSLKOA3US3JROZNEQVTTLJME22KPNRZWSYSYKZZWIR3LORNEOTLUMMZE42DCI5KWSTCDJJXGEM22NRRW2NLIMJWU43CMLBBHMYSHNRVGKU2JONEW2RTLMRWUM5KZGJLGWTCXKJUGIR2FORRUQSTWMRDVM2TEI5WHMYTJJJSGMWBQHUXGGYLLOJYXO23DFNXUCOBVLF5FMN2NGF4DGUTMF5XDEYJLJJLW2M2SOB5GI5JXGQ3WCMKFKRRSW6CMHAXWU2LVMVVGIUSUPBTXASJQKVAVETSZOVRUSQLMIN5EO2LHO5QWYYZZHFBVUMLEIFVWGYJUMRLDAMZTHBIHO3KWNRQXMSSQGRYEU6CJJE4UINSVIZGFKYKWKBVGWV2KORRUINTQMFWDM32PMZDW4SZSPJIEWSSSNVDUQVRTMVNHO4KGMUVW6N3LF5ZSWQKUJZUFAWTHKMXUWVSZM4XUWK3MI5IHOTBXNJBHQSJXI5HWC2ZWKVQWSYKIN5SWWMCSKRXTOMSEKE6T2"

  sleep 2s

  
  printf "\n%s" \
    "[$vault_node_name] List the raft cluster members" \
    ""
  vault_5 operator raft list-peers

  printf "\n%s" \
    "[$vault_node_name] Vault status" \
    ""
  vault_5 status
}

function setup_vault_6 {
  set -aex

  local vault_node_name="vault_6"
  local vault_config_file=$demo_home/config/config-$vault_node_name.hcl
  local vault_log_file=$demo_home/logs/$vault_node_name.log

  printf "\n%s" \
    "[$vault_node_name] starting Vault server @ $vault_node_name" \
    ""

  VAULT_API_ADDR=http://127.0.0.1:8260 vault server -log-level=trace -config "$vault_config_file" > "$vault_log_file" 2>&1 &
  #while ! nc -w 1 localhost 8260 </dev/null; do sleep 1; done
  sleep 2s

  #printf "\n%s" \
   # "[$vault_node_name] Unseal $vault_node_name" \
    #""
  #vault_6 operator unseal `cat $demo_home/unsealKey2`

  sleep 1s

  printf "\n%s" \
    "[$vault_node_name] Join the raft cluster" \
    ""
  #vault_6 operator raft join

  sleep 15s

  vault_6 login `cat $demo_home/rootToken2`

  printf "\n%s" \
    "[vault_6] Installing License" \
    ""
  vault_6 write sys/license text="02MV4UU43BK5HGYYTOJZWFQMTMNNEWU33JJZ5GGM2PIRWG2TSXKV2E6RCCNFMWSMBTJZLU42KMKRGTCWLNIV2FU3KVGNMVOSTLJVDVC6C2IREXUSLJO5UVSM2WPJSEOOLULJMEUZTBK5IWST3JJEZVUR2SNFMWUQTMLFUTANCNKRDGQTCUJF5E4VCVORHFOTTKLF4TC222I5MXOTSEKV5FSVDENBNGUZ3JJRBUU4DCNZHDAWKXPBZVSWCSOBRDENLGMFLVC2KPNFEXCSLJO5UWCWCOPJSFOVTGMRDWY5C2KNETMSLKJF3U22SBORGUIZ3UJVKEMVKNKRITMTSEIU3E22TLOVGXUQJRJZCE26COKRCTIV3JJFZUS3SOGBMVQSRQLAZVE4DCK5KWST3JJF4U2RCJO5GFIQJUJRKEK6CWIRAXOT3KIF3U62SBO5LWSSLTJFWVMNDDI5WHSWKYKJYGEMRVMZSEO3DULJJUSNSJNJEXOTLKIV2E2RDHORGVIRSVJVVE2NSOKRVTMTSUNN2U6VDLGVLWSSLTJFXFE3DDNUYXAYTNIYYGCVZZOVMDGUTQMJLVK2KPNFEXSTKEJF4EYVCBGVGFIRJRKZCEC52PNJAXOT3KIF3VO2KJONEW4QTZMIZFEMKZGNIWST3JJIZFSWCWONSEGSLTJFWVU42ZK5SHUSLKOA3US3JROZNEQVTTLJME22KPNRZWSYSYKZZWIR3LORNEOTLUMMZE42DCI5KWSTCDJJXGEM22NRRW2NLIMJWU43CMLBBHMYSHNRVGKU2JONEW2RTLMRWUM5KZGJLGWTCXKJUGIR2FORRUQSTWMRDVM2TEI5WHMYTJJJSGMWBQHUXGGYLLOJYXO23DFNXUCOBVLF5FMN2NGF4DGUTMF5XDEYJLJJLW2M2SOB5GI5JXGQ3WCMKFKRRSW6CMHAXWU2LVMVVGIUSUPBTXASJQKVAVETSZOVRUSQLMIN5EO2LHO5QWYYZZHFBVUMLEIFVWGYJUMRLDAMZTHBIHO3KWNRQXMSSQGRYEU6CJJE4UINSVIZGFKYKWKBVGWV2KORRUINTQMFWDM32PMZDW4SZSPJIEWSSSNVDUQVRTMVNHO4KGMUVW6N3LF5ZSWQKUJZUFAWTHKMXUWVSZM4XUWK3MI5IHOTBXNJBHQSJXI5HWC2ZWKVQWSYKIN5SWWMCSKRXTOMSEKE6T2"

  sleep 2s

  
  printf "\n%s" \
    "[$vault_node_name] List the raft cluster members" \
    ""
  vault_6 operator raft list-peers

  printf "\n%s" \
    "[$vault_node_name] Vault status" \
    ""
  vault_6 status
}

function create {
  case "$1" in
    network)
      shift ;
      create_network "$@"
      ;;
    config)
      shift ;
      create_config "$@"
      ;;
    *)
      printf "\n%s" \
      "Creates resources for the cluster." \
      "Usage: $script_name create [network|config]" \
      ""
      ;;
  esac
}

function setup {
  case "$1" in
    vault_1)
      setup_vault_1
      ;;
    vault_2)
      setup_vault_2
      ;;
    vault_3)
      setup_vault_3
      ;;
    vault_4)
      setup_vault_4
      ;;
    vault_5)
      setup_vault_5
      ;;
    vault_6)
      setup_vault_6
      ;;
    all)
      for vault_setup_function in setup_vault_1 setup_vault_2 setup_vault_3 setup_vault_4 setup_vault_5 setup_vault_6 ; do
        $vault_setup_function
      done
      ;;
    *)
      printf "\n%s" \
      "Sets up resources for the cluster" \
      "Usage: $script_name setup [all|vault_1|vault_2|vault_3|vault_4|vault_5|vault_6]" \
      ""
      ;;
  esac
}

case "$1" in
  create)
    shift ;
    create "$@"
    ;;
  setup)
    shift ;
    setup "$@"
    ;;
  vault_1)
    shift ;
    vault_1 "$@"
    ;;
  vault_2)
    shift ;
    vault_2 "$@"
    ;;
  vault_3)
    shift ;
    vault_3 "$@"
    ;;
  vault_4)
    shift ;
    vault_4 "$@"
    ;;
  vault_5)
    shift ;
    vault_5 "$@"
    ;;
  vault_6)
    shift ;
    vault_6 "$@"
    ;;
  status)
    status
    ;;
  start)
    shift ;
    start "$@"
    ;;
  stop)
    shift ;
    stop "$@"
    ;;
  clean)
    stop all
    clean
    ;;
  *)
    printf "\n%s" \
      "This script helps manages a Vault HA cluster with raft storage." \
      "View the README.md the complete guide at https://learn.hashicorp.com/vault/beta/raft-storage" \
      "" \
      "Usage: $script_name [create|setup|status|stop|clean|vault_1|vault_2|vault_3]" \
      ""
    ;;
esac
