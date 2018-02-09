#! /bin/bash

export NBI_URL=https://localhost:9999/osm
USERNAME=admin
PASSWORD=admin
PROJECT=admin
VIM=ost2-mrt-tid   #OST2_MRT  #ost2-mrt-tid

DESCRIPTORS=/home/ubuntu/descriptors #../local/descriptors
DESCRIPTORS=../local/descriptors

VNFD1=${DESCRIPTORS}/ping_vnf.tar.gz
VNFD2=${DESCRIPTORS}/pong_vnf.tar.gz
VNFD3=${DESCRIPTORS}/cirros_vnfd.yaml

NSD1=${DESCRIPTORS}/ping_pong_ns.tar.gz
NSD2=${DESCRIPTORS}/cirros_2vnf_ns.tar.gz
NSD3=${DESCRIPTORS}/cirros_nsd.yaml

[ -f "$VNFD1" ] || ! echo "not found ping_vnf.tar.gz. Set DESCRIPTORS variable to a proper location" || exit 1
[ -f "$VNFD2" ] || ! echo "not found pong_vnf.tar.gz. Set DESCRIPTORS variable to a proper location" || exit 1
[ -f "$VNFD3" ] || ! echo "not found cirros_vnfd.yaml. Set DESCRIPTORS variable to a proper location" || exit 1
[ -f "$NSD1" ] || ! echo "not found ping_pong_ns.tar.gz. Set DESCRIPTORS variable to a proper location" || exit 1
[ -f "$NSD2" ] || ! echo "not found cirros_2vnf_ns.tar.gz. Set DESCRIPTORS variable to a proper location" || exit 1
[ -f "$NSD3" ] || ! echo "not found cirros_nsd.yaml. Set DESCRIPTORS variable to a proper location" || exit 1

#get token
TOKEN=`curl --insecure -H "Content-Type: application/yaml" -H "Accept: application/yaml"  --data "{username: $USERNAME, password: $PASSWORD, project_id: $PROJECT}" ${NBI_URL}/token/v1 2>/dev/null | awk '($1=="id:"){print $2}'`;
echo token: $TOKEN




# VNFD
#########
#insert PKG
VNFD1_ID=`curl --insecure -w "%{http_code}\n" -H "Content-Type: application/gzip" -H "Accept: application/yaml" -H "Authorization: Bearer $TOKEN"   --data-binary "@$VNFD1" ${NBI_URL}/vnfpkgm/v1/vnf_packages 2>/dev/null | awk '($1=="id:"){print $2}'` 
echo ping_vnfd: $VNFD1_ID

VNFD2_ID=`curl --insecure -w "%{http_code}\n" -H "Content-Type: application/gzip" -H "Accept: application/yaml" -H "Authorization: Bearer $TOKEN"   --data-binary "@$VNFD2" ${NBI_URL}/vnfpkgm/v1/vnf_packages 2>/dev/null | awk '($1=="id:"){print $2}'`
echo pong_vnfd: $VNFD2_ID



# NSD
#########
#insert PKG
NSD1_ID=`curl --insecure -w "%{http_code}\n" -H "Content-Type: application/gzip" -H "Accept: application/yaml" -H "Authorization: Bearer $TOKEN"   --data-binary "@$NSD1" ${NBI_URL}/nsd/v1/ns_descriptors 2>/dev/null | awk '($1=="id:"){print $2}'`
echo ping_pong_nsd: $NSD1_ID


# NSRS
##############
#add nsr
NSR1_ID=`curl --insecure -w "%{http_code}\n" -H "Content-Type: application/yaml" -H "Accept: application/yaml" -H "Authorization: Bearer $TOKEN"   --data "{ nsDescription: default description, nsName: NSNAME, nsdId: $NSD1_ID, ssh-authorized-key: [ {key-pair-ref: gerardo}, {key-pair-ref: alfonso}], vimAccountId: $VIM }"  ${NBI_URL}/nslcm/v1/ns_instances 2>/dev/null | awk '($1=="id:"){print $2}'` ;
echo ping_pong_nsr: $NSR1_ID


echo '
curl --insecure -w "%{http_code}\n" -H "Content-Type: application/yaml" -H "Accept: application/yaml" -H "Authorization: Bearer '$TOKEN'"  '${NBI_URL}'/nslcm/v1/ns_instances/'$NSR1_ID' 2>/dev/null | grep -e detailed-status -e operational-status -e config-status'




