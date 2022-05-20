read -p "Insert the DNS Hosted Zone:" dns_name

#Get  your External IP address
ExternalIP=$(curl -s ipinfo.io/ip)

#Run terraform script
terraform init
terraform apply -var-file=variable.tfvars -var="dns_name=$dns_name"  -var="ExternalIP=$ExternalIP" -auto-approve



#Deploy the application to the environment
#aws  elasticbeanstalk update-environment --environment-name $(terraform output env_namePRD) --version-label $(terraform output app_versionPRD)
#aws  elasticbeanstalk update-environment --environment-name $(terraform output env_nameTST) --version-label $(terraform output app_versionTST)

envnamePRD="django-env-prd"
versionPRD="django-app-prd-v1"
envnameTST="django-env-tst"
versionTST="django-app-tst-v1"
aws  elasticbeanstalk update-environment --environment-name $envnamePRD --version-label  $versionPRD
aws  elasticbeanstalk update-environment --environment-name $envnameTST --version-label  $versionTST