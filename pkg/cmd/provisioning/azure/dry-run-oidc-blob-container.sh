#!/usr/bin/env bash

set -e

region={{.Region}}
resource_group_name={{.ResourceGroupName}}
storage_account_name={{.StorageAccountName}}
blob_container_name={{.BlobContainerName}}
resource_tags={{.ResourceTags}}

json_object_to_kv() {
  echo $1 | jq -rc 'to_entries | map("\(.key)=\(.value | tostring)") | .[]' | tr '\n' ' ' | sed 's/ $//'
}

ensure_tags() {
  local resource_id="$1"
  local existing_tags=$(az tag list --resource-id "${resource_id}" | jq -cM ".properties.tags")
  local new_tags=$(echo "{} ${resource_tags}" | jq -scM add)
  local new_tags_list=$(json_object_to_kv "${new_tags}")
  az tag update --resource-id "${resource_id}" --operation Replace --tags ${new_tags_list} >> /dev/null
}

ensure_resource_group() {
  local group_id=$(az group list | jq -r ".[] | select(.name == \"${resource_group_name}\" and .location == \"${region}\") | .id")
  if [ -z "${group_id}" ]; then
    group_id=$(az group create --name "${resource_group_name}" --location "${region}" | jq -r '.id')
  fi
  echo $group_id
}

# main
echo "Creating resource group ${resource_group_name} if it does not exist"
group_id=$(ensure_resource_group)
echo "Ensuring tags on resource group ${resource_group_name}"
ensure_tags "${group_id}"

echo "Done!"