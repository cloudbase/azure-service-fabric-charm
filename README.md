
# Overview

Azure Service Fabric is a distributed systems platform that makes it easy to package, deploy, and manage scalable and reliable microservices. Service Fabric also addresses the significant challenges in developing and managing cloud applications.

# Configuration

Plan your cluster configuration before deploying the charm as the current release doesn't support dynamically changing the configuration options.

Supported deployment scenarios at the moment are:

- Unsecured cluster node-to-node and client-to-node. This is the default behavior. In this way the charm doesn't have any relation and it can be deployed standalone, but this is not recommended in the production due to security concerns.

- Secured using Active Directory Windows credentials. This requires a relation with the [active directory charm](https://jujucharms.com/u/cloudbaseit/active-directory). This can be achieved by deploying the charm with `security-type` config option set to `Windows`.

For both scenarios make sure you properly adjust the `reliability-level` config option as this dictates the minimum number of units necessary to form the cluster. By default the reliability level is set to `Bronze` and it requires at least three nodes to form the cluster. More info about reliability levels can be found at the following [url](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-cluster-manifest#reliability).

Take care when using Juju OpenStack provider to always set the config option `change-hostname` to `True`. Due to the fact that Juju spawns nova instances with long names, all instances end up with the same prefix. After instances finish the initializing process, they all have the same hostname as cloudbase-init just gets the first 15 characters from the nova instance name. This is problematic when joining an Active Directory domain. Config option `change-hostname` will enable the charm to rename the computer name to a unique name formed from unit name and unit number.

# Usage

The charm has two dependencies. Whenever someone deploys the charm, these needs to be passed as Juju resources (resources are available in Juju versions >= 2.0).

Make sure you download the dependencies before you deploy the charm:

- Full version of .NET framework version 4.5.1 or higher. This can be obtained from the following [download url](https://www.microsoft.com/en-us/download/details.aspx?id=40779)
- Service Fabric standalone zip package. This can be download from the Microsoft website at the following [url](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-cluster-creation-for-windows-server), section *Download the Service Fabric standalone package*.

When you have your resources ready, you can deploy the charm. The following commands will deploy a cluster using AD Windows security type, `Bronze` reliability level and HAProxy load balancer in order to do a reverse proxy for the API and GUI port.

    juju deploy  cs:~cloudbaseit/azure-service-fabric-1 --resource dotnet-installer="<dot_net_framework_installed_path>" \
                                                        --resource asf-zip-package="<service_fabric_zip_package_path>" \
                                                        --num-units 3
    juju config azure-service-fabric security-type=Windows \
                                     change-hostname=True
    juju deploy cs:~cloudbaseit/active-directory
    juju config active-directory administrator-password="<secure_password>" \
                                 safe-mode-password: "<secure_password>" \
                                 domain-user: "jujuadmin" \
                                 domain-user-password: "<secure_password>" \
                                 domain-name: "<fully_qualified_domain_name>" \
                                 change-hostname: True
    juju deploy cs:haproxy
    juju expose haproxy

Once the deployment finishes, find the public address of HAProxy unit and you can access the web portal the the following url: `http://<haproxy_public_address>:19080`. And also if you'd like to query the API, this can be done at the following endpoint: `<haproxy_public_address>:19000`.
