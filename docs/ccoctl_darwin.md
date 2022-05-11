# How to run ccoctl on macOS

## Context
The `ccoctl` command extracted from the image cannot be run directly in a `Darwin` kernel, as it was compiled for a `Linux` kernel.
But you can run the command inside a ontainer on a macOS.

## Requirement
- Docker (or equivalent) should be installed on macOS
- Having the install-config.yaml and manifests created
- Having the credential-requests directory (step 2 from previous documentation) in the same directory that the `ccoctl` command.

## How to create the cloud credentials on macOS
1. Set the variables you will need to use in your container
    - AWS environment
      ~~~
      INSTALL_CONFIG_FILE=install-config.yaml
      CCO_NAME=$(yq -r '.metadata.name' $ {INSTALL_CONFIG_FILE})
      CCO_REGION=$(yq -r '.platform.aws.region' ${INSTALL_CONFIG_FILE})
      ~~~
    - GCP environment
      ~~~
      INSTALL_CONFIG_FILE=install-config.yaml
      CCO_NAME=$(yq -r '.metadata.name' ${INSTALL_CONFIG_FILE})
      CCO_REGION=$(yq -r '.platform.gcp.region' ${INSTALL_CONFIG_FILE})
      CCO_PROJECT=$(yq -r '.platform.gcp.projectID' ${INSTALL_CONFIG_FILE})
      ~~~

2. Start you container using the ubi8-minimal:latest
    ~~~
    docker run --rm -ti -v ${PWD}:/mnt -e CCO_NAME=${CCO_NAME} -e CCO_REGION=${CCO_REGION} -e CCO_PROJECT=${CCO_PROJECT} redhat/ubi8-minimal
    ~~~
    This will start the container, with all variables already exported, and the current directory (with the `ccoctl` command and the `credreqs` folder) available in `/mnt`

3. Run the command in the container
    - for AWS
      ~~~
      cd /mnt
      chmod +x ./ccoctl
      ./ccoctl aws create-all --name <aws_infra_name> --region <aws_region> --credentials-requests-dir ./credreqs --output-dir cco
      ~~~
    - for GCP
      ~~~
      cd /mnt
      chmod +x ./ccoctl
      ./ccoctl gcp create-all --name=${CCO_NAME} --region=${CCO_REGION} --project=${CCO_PROJECT} --credentials-requests-dir=./credreqs --output-dir=cco
      ~~~
    This will create the Cloud Credentials in the folder `/mnt/cco` which will be available in your local directory on macOS.
