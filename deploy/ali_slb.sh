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

  if [ -z "$Ali_SLB_Access_Id" ] || [ -z "$Ali_SLB_Access_Secret" ]; then
    Ali_SLB_Access_Id=""
    Ali_SLB_Access_Secret=""
    _err "You don't specify aliyun api key or secret yet"
    return 1
  fi

  #save the api key and secret to the account conf file.
  _saveaccountconf_mutable Ali_SLB_Access_Id "$Ali_SLB_Access_Id"
  _saveaccountconf_mutable Ali_SLB_Access_Secret "$Ali_SLB_Access_Secret"

  #_ali_regions && _ali_rest "Regions"
  _add_slb_ca_query "$_ckey" "$_cfullchain" && _ali_rest "Upload Server Certificate"

  #returns 0 means success, otherwise error.
  return 0
}

########  Private functions #####################
_ali_rest() {

  signature=$(printf "%s" "GET&%2F&$(_ali_urlencode "$query")" | _hmac "sha1" "$(printf "%s" "$Ali_SLB_Access_Secret&" | _hex_dump | tr -d " ")" | _base64)
  signature=$(_ali_urlencode "$signature")
  url="$Ali_SLB_Endpoint?$query&Signature=$signature"
  _debug "0000000000000000000"
  if ! response="$(_get "$url" "" 3000)"; then
    _debug "1111111111111111111"
    _err "Error <$1>"
    return 1
  fi

  if [ -z "$2" ]; then
    message="$(printf "%s" "$response" | _egrep_o "\"Message\":\"[^\"]*\"" | cut -d : -f 2 | tr -d \")"
    if [ -n "$message" ]; then
      _debug "2222222222222222222222"
      _err "$message"
      return 1
    fi
  fi

  _debug "3333333333333333333"
  _debug response "$response"

  # 上传证书成功, 将证书绑定到监听端口443
  #_set_slb_server_certificate "$_slbId" "$_serverCertId" && _ali_rest "Set Server Certificate on port 443"
  _set_slb_server_certificate "lb-bp1nzt9lv390kd79uztea" "1509613042118023_1658eb46780_819298432_-1697713486" && _ali_rest "Set Server Certificate on port 443"

  return 0
}

_ali_urlencode() {
  echo $(php -r "echo str_replace(['+','*','%7E'], ['%20','%2A','~'], urlencode(\"$1\"));")
}

_ali_nonce() {
  date +"%s%N"
}

_ali_slb_regions() {
  query=''
  query=$query'AccessKeyId='$Ali_SLB_Access_Id
  query=$query'&Action=DescribeRegions'
  query=$query'&Format=json'
  query=$query'&SignatureMethod=HMAC-SHA1'
  query=$query'&SignatureNonce='$(_ali_nonce)
  query=$query'&SignatureVersion=1.0'
  query=$query'&Timestamp='$_timestamp
  query=$query'&Version=2014-05-15'
}

#_add_slb_ca_query "$_ckey" "$_cfullchain"
_add_slb_ca_query() {
  ca_key=$(_readfile "$1")
  ca_cert=$(_readfile "$2")
  query=''
  #query=$query'AccessKeyId='$Ali_SLB_Access_Id
  #query=$query'&Action=UploadServerCertificate'
  #query=$query'&Format=json'
  #query=$query'&PrivateKey='$ca_key
  #query=$query'&RegionId=cn-hangzhou'
  #query=$query'&ServerCertificate='$ca_cert
  #query=$query'&ServerCertificateName='$(_date)
  #query=$query'&SignatureMethod=HMAC-SHA1'
  #query=$query'&SignatureNonce='$(_ali_nonce)
  #query=$query'&SignatureVersion=1.0'
  #query=$query'&Timestamp='$(_timestamp)
  #query=$query'&Version=2014-05-15'

  query=$query'AccessKeyId='$Ali_SLB_Access_Id
  query=$query'&Action=UploadServerCertificate'
  query=$query'&Format=json'
  query=$query'&PrivateKey='$ca_key
  query=$query'&RegionId=cn-hangzhou'
  query=$query'&ServerCertificate='$ca_cert
  query=$query'&ServerCertificateName='$(_date)
  query=$query'&SignatureMethod=HMAC-SHA1'
  query=$query'&SignatureNonce='$(_ali_nonce)
  query=$query'&SignatureVersion=1.0'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&Version=2014-05-15'
}

#_set_slb_server_certificate "$_slbId" "$_serverCertId"
_set_slb_server_certificate() {
  slbId=$(_readfile "$1")
  serverCertId=$(_readfile "$2")
  query=''
  query=$query'Action=SetLoadBalancerHTTPSListenerAttribute'
  query=$query'&RegionId=cn-hangzhou'
  query=$query'&LoadBalancerId='$slbId
  query=$query'&ListenerPort=443'
  query=$query'&ServerCertificateId='$serverCertId
  query=$query'&Bandwidth=-1'
  query=$query'&StickySession=on'
  query=$query'&StickySessionType=insert'
  query=$query'&HealthCheck=on'
  query=$query'&Version=2014-05-15'
  query=$query'&AccessKeyId='$Ali_SLB_Access_Id
  query=$query'&SignatureMethod=HMAC-SHA1'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&SignatureVersion=1.0'
  query=$query'&SignatureNonce='$(_ali_nonce)
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