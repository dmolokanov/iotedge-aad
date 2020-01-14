# Emulates iotedge using Azure AD identities to access Azure Resources

## Usage
```bash
# 1. Build project in release mode
cargo build --release

# 2. Create app registration for a new "device" with certificate to get access token
az ad sp create-for-rbac \
    -n edgy-1 \
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
moduleId=$(./target/release/iotedge-aad identity provision module-a --cert module-a/combined.pem)

# 6. Assign a role "Reader" to the resource group for the module identity
rgId=$(az group create -n edgy-1-rg -l westus) --query 'id' -o tsv
az storage account create -n edgy1sa -g edgy-1-rg -l westus --sku Standard_LRS
az role assignment create --role Reader --assignee $moduleId  --scope $rgId

# 7. Try to get an access token for module
token=$(./target/release/iotedge-aad token module-a)

# 7. Using an access token obtained on previous step try to get 

```