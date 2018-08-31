#!/bin/bash

# Attention:
#This file name is "ali_slb.sh"
#So, here must be a method  ali_slb_deploy()
#Which will be called by acme.sh to deploy the cert
#returns 0 means success, otherwise error.

########  Public functions #####################
# 参考: https://github.com/Neilpang/acme.sh/wiki/DNS-API-Dev-Guide
# aliyun RPC API签名算法: https://help.aliyun.com/document_detail/66384.html?spm=5176.11065259.1996646101.searchclickresult.82064a56fBWU0Y
#domain keyfile certfile cafile fullchain
#Ali_SLB_Access_Id="My_SLB_Access_Id"
#Ali_SLB_Access_Secret="My_SLB_Access_Secret"
#Ali_SLB_Id="Ali_SLB_Id"
Ali_SLB_Endpoint="https://slb.aliyuncs.com/"

ali_slb_deploy() {
  _cdomain="$1"
  _ckey="$2"
  _ccert="$3"
  _cca="$4"
  _cfullchain="$5"

  _debug _cdomain "$_cdomain"
  _debug _ckey "$_ckey"
  _debug _ccert "$_ccert"
  _debug _cca "$_cca"
  _debug _cfullchain "$_cfullchain"

  if [ -z "$Ali_SLB_Access_Id" ] || [ -z "$Ali_SLB_Access_Secret" ] || [ -z "$Ali_SLB_Id" ] || [ -z "$Ali_SLB_Region" ]; then
    Ali_SLB_Access_Id=""
    Ali_SLB_Access_Secret=""
    Ali_SLB_Id=""
    Ali_SLB_Region=""
    _err "You don't specify aliyun api access key or secret or SLB_ID or SLB_Region yet"
    return 1
  fi

  #save the api key and secret to the account conf file.
  _saveaccountconf_mutable Ali_SLB_Access_Id "$Ali_SLB_Access_Id"
  _saveaccountconf_mutable Ali_SLB_Access_Secret "$Ali_SLB_Access_Secret"
  _saveaccountconf_mutable Ali_SLB_Id "$Ali_SLB_Id"
  _saveaccountconf_mutable Ali_SLB_Region "$Ali_SLB_Region"

  _add_slb_ca_query "$_ckey" "$_cfullchain" && _ali_rest "UploadServerCertificate"

  #returns 0 means success, otherwise error.
  return 0
}

########  Private functions #####################
_ali_rest() {

  signature=$(printf "%s" "GET&%2F&$(_ali_urlencode "$query")" | _hmac "sha1" "$(printf "%s" "$Ali_SLB_Access_Secret&" | _hex_dump | tr -d " ")" | _base64)
  signature=$(_ali_urlencode "$signature")
  url="$Ali_SLB_Endpoint?$query&Signature=$signature"
  if ! response="$(_get "$url" "" 3000)"; then
    _err "Error <$1>"
    return 1
  fi

  if [ -z "$2" ]; then
    message="$(printf "%s" "$response" | _egrep_o "\"Message\":\"[^\"]*\"" | cut -d : -f 2 | tr -d \")"
    if [ -n "$message" ]; then
      _err "$message"
      return 1
    fi
  fi

  _debug response "$response"
  local _serverCertId=$(get_json_value "$response" "ServerCertificateId")

  if [ "UploadServerCertificate" == $1 ]; then
    _debug "上传证书成功, 将证书绑定到监听端口443"
    _set_slb_server_certificate "$Ali_SLB_Id" "$_serverCertId" && _ali_rest "Set Server Certificate on port 443"
  fi

  return 0
}

_ali_urlencode() {
  echo $(php -r "echo str_replace(['+','*','%7E'], ['%20','%2A','~'], urlencode(\"$1\"));")
}

_ali_nonce() {
  date +"%s%N"
}

#_add_slb_ca_query "$_ckey" "$_cfullchain"
_add_slb_ca_query() {
  local ca_key=$(_readfile "$1")
  local ca_cert=$(_readfile "$2")

  query=''
  query=$query'AccessKeyId='$Ali_SLB_Access_Id
  query=$query'&Action=UploadServerCertificate'
  query=$query'&Format=json'
  query=$query'&PrivateKey='$ca_key
  query=$query'&RegionId='$Ali_SLB_Region
  query=$query'&ServerCertificate='$ca_cert
  query=$query'&ServerCertificateName='$_date
  query=$query'&SignatureMethod=HMAC-SHA1'
  query=$query'&SignatureNonce='$(_ali_nonce)
  query=$query'&SignatureVersion=1.0'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&Version=2014-05-15'
}

#_set_slb_server_certificate "$slbId" "$serverCertId"
_set_slb_server_certificate() {
  local slbId=$1
  local serverCertId=$2

  query=''
  query=$query'AccessKeyId='$Ali_SLB_Access_Id
  query=$query'&Action=SetLoadBalancerHTTPSListenerAttribute'
  query=$query'&Bandwidth=-1'
  query=$query'&CookieTimeout=86400'
  query=$query'&HealthCheck=off'
  query=$query'&ListenerPort=443'
  query=$query'&LoadBalancerId='$slbId
  query=$query'&RegionId='$Ali_SLB_Region
  query=$query'&ServerCertificateId='$serverCertId
  query=$query'&SignatureMethod=HMAC-SHA1'
  query=$query'&SignatureNonce='$(_ali_nonce)
  query=$query'&SignatureVersion=1.0'
  query=$query'&StickySession=on'
  query=$query'&StickySessionType=insert'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&Version=2014-05-15'
}

function get_json_value()
{
  local json=$1
  local key=$2

  if [[ -z "$3" ]]; then
    local num=1
  else
    local num=$3
  fi

  local value=$(echo "${json}" | awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'${key}'\042/){print $(i+1)}}}' | tr -d '"' | sed -n ${num}p)

  echo ${value}
}

_readfile() {
  echo $(php -r "echo str_replace(['+','*','%7E'], ['%20','%2A','~'], urlencode(file_get_contents(\"$1\")));")
}

_timestamp() {
  date -u +"%Y-%m-%dT%H%%3A%M%%3A%SZ"
}

_date() {
  date -u +"%Y%m%d"
}