# Emulates iotedge using Azure AD identities to access Azure Resources

## Demo
```bash
# 1. Build project in release mode
cargo build --release

# 2. Create app registration for a new "device" with certificate to get access token
az ad sp create-for-rbac \
    -n newdevice \
    --create-cert \
    --query '{ clientId: appId, tenantId: tenant, cert: fileWithCertAndPrivateKey }' \
    -o json \
    > context.json

# 3. Add "Application.ReadWrite.OwnedBy" permission for "Microsoft Graph" to be able to create another service principals
az ad app permission add \
    --id $(cat context.json | jq -r '.clientId') \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions 18a4783c-866b-4cc7-a460-3d5e5662c884=Role \
    -o json

# NOTE: There is a bug in the azure-cli tool that prevent user grant permission with az tool.
# 4. Manually sign-in Azure portal. App registration -> edgy-1 -> Api permissions -> Grant admin consent for Default Directory

# 5. Provision an identity for module. It will use a certificate created on step 2 to obtain an access token.
moduleId=$(./target/release/iotedge-aad identity provision newmodule --cert <path to module certificate/private key pem file>)

# 6. Assign a role "Reader" to the resource group for the module identity
rgId=$(az group create -n newdevice-rg -l westus --query 'id' -o tsv)
saId=$(az storage account create -n newdevicesa -g newdevice-rg -l westus --sku Standard_LRS --query 'id' -o tsv)
az role assignment create --role Reader --assignee $moduleId  --scope $rgId

# 7. Try to get an access token for module
token=$(./target/release/iotedge-aad token newmodule --id $moduleId)

# 7. Using an access token obtained on previous step try to get 
subscriptionId=$(echo $saId | awk -F / '{print $3}')
curl "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01" \
    --header "Authorization: Bearer $token"
```

## Usage
```
iotedge aad module identities integration 

USAGE:
    iotedge-aad [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --context <context>     [default: context.json]

SUBCOMMANDS:
    help        Prints this message or the help of the given subcommand(s)
    identity    Manages module identities
    token       Obtains module access token
```

## Links

- [Service Principals](https://docs.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-beta)
- [Applications](https://docs.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-beta)
- [Azure REST API](https://docs.microsoft.com/en-us/rest/api/azure/)
- [OAuth2 client credentials flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)


Add/Delete api permissions
- https://stackoverflow.com/questions/57316875/add-or-delete-an-apps-api-permissions-requiredresourceaccess-via-microsoft-gr
- https://docs.microsoft.com/en-us/graph/api/application-update?view=graph-rest-1.0&tabs=http

Gettings access without a user
- https://docs.microsoft.com/en-us/graph/auth-v2-service

How to get a list of permission ids in Graph API: 
```
GET https://graph.microsoft.com/beta/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'
```
