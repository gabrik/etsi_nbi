#! /bin/bash

export NBI_URL=https://localhost:9999/osm
USERNAME=admin
PASSWORD=admin
PROJECT=admin



#get token
TOKEN=`curl --insecure -H "Content-Type: application/yaml" -H "Accept: application/yaml"  --data "{username: $USERNAME, password: $PASSWORD, project_id: $PROJECT}" ${NBI_URL}/token/v1 2>/dev/null | awk '($1=="id:"){print $2}' ` ; echo $TOKEN


echo  deleting all
#DELETE ALL

for url_item in nslcm/v1/ns_instances nsd/v1/ns_descriptors vnfpkgm/v1/vnf_packages
do
    for ITEM_ID in `curl --insecure -w "%{http_code}\n" -H "Content-Type: application/yaml" -H "Accept: application/yaml" -H "Authorization: Bearer $TOKEN"  ${NBI_URL}/${url_item} 2>/dev/null | awk '($1=="_id:") {print $2}'` ;
    do
        curl --insecure -w "%{http_code}\n" -H "Content-Type: application/yaml" -H "Accept: application/yaml" -H "Authorization: Bearer $TOKEN"  ${NBI_URL}/${url_item}/$ITEM_ID -X DELETE
    done
done

# curl --insecure  ${NBI_URL}/test/prune

