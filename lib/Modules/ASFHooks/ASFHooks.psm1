# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

Import-Module JujuHooks
Import-Module JujuUtils
Import-Module JujuWindowsUtils
Import-Module ADCharmUtils

$ASF_HOME_DIR = Join-Path $env:SystemDrive "ServiceFabric"
$ASF_PKG_DIR = Join-Path $ASF_HOME_DIR "Package"
$ASF_RUNTIME_CAB_FILE_PATH = Join-Path $ASF_PKG_DIR "MicrosoftAzureServiceFabric.cab"
$ASF_AD_USER_NAME = "asf-user"
$ASF_AD_ADMIN_NAME = "asf-admin"
$ASF_AD_GROUP_NAME = "asf-group"
$LOCAL_USER_FULL_NAME = "ASF Juju User"
$LOCAL_USER_DESCRIPTION = "Local administrator user used by the Juju charm"
$UNSECURE_SECURITY_TYPE = 'Unsecure'
$WINDOWS_SECURITY_TYPE = 'Windows'
$CERTIFICATE_SECURITY_TYPE = 'x509'
$VALID_SECURITY_TYPES = @($UNSECURE_SECURITY_TYPE, $WINDOWS_SECURITY_TYPE, $CERTIFICATE_SECURITY_TYPE)
$DEFAULT_FABRIC_LOG_ROOT = Join-Path $ASF_HOME_DIR "Log"
$DEFAULT_FABRIC_DATA_ROOT = Join-Path $ASF_HOME_DIR "FabricDataRoot"
$DEFAULT_DIAGNOSTICS_STORE = Join-Path $ASF_HOME_DIR "DiagnosticsStore"
$ADMINISTRATORS_GROUP_SID = "S-1-5-32-544"
$COMPUTERNAME = [System.Net.Dns]::GetHostName()
# Mapping between reliability levels and the minimum number of primary nodes
# required to achieve it.
$VALID_RELIABILITY_LEVELS = @{
    "Bronze"   = 3
    "Silver"   = 5
    "Gold"     = 7
    "Platinum" = 9
}

try {
    # NOTE(ibalutoiu):
    # If DeploymentComponents is not added in PATH, the Azure Service Provider
    # PowerShell cmdlets complain because they can't find the 'FabricCommon.dll'
    $env:PATH += ";$ASF_PKG_DIR\DeploymentComponents"
    Import-Module "$ASF_PKG_DIR\DeploymentComponents\ServiceFabric.psd1"
} catch {
    Write-JujuWarning "Azure Service Fabric package is not yet installed."
}


function Get-CharmConfigContext {
    if($Global:ASF_CHARM_CFG) {
        return $Global:ASF_CHARM_CFG
    }
    # Array with all the config options used by the charm.
    $charmConfigs = @(
        'cluster-name',
        'security-type',
        'reliability-level',
        'fault-domain-name',
        'upgrade-domain-name',
        'client-connection-endpoint-port',
        'cluster-connection-endpoint-port',
        'lease-driver-endpoint-port',
        'service-connection-endpoint-port',
        'http-gateway-endpoint-port',
        'ephemeral-start-port',
        'ephemeral-end-port',
        'application-start-port',
        'application-end-port',
        'change-hostname'
    )
    $cfgCtxt = @{}
    $cfg = Get-JujuCharmConfig
    foreach($key in $charmConfigs) {
        if($cfg[$key] -eq $null) {
            Throw "Config option $key is mandatory"
        }
        $cfgCtxt[($key -replace '-', '_')] = $cfg[$key]
    }
    # Validate the cluster security type
    if($cfgCtxt['security_type'] -notin $VALID_SECURITY_TYPES) {
        Throw ("{0} is not a valid cluster security type." -f @($cfgCtxt['security_type']))
    }
    # Validate reliability level config option
    if($cfgCtxt['reliability_level'] -notin $VALID_RELIABILITY_LEVELS.Keys) {
        Throw ("{0} is not a valid reliability level." -f @($cfgCtxt['reliability_level']))
    }
    # Validate ephemeral port range
    if(($cfgCtxt['ephemeral_end_port'] - $cfgCtxt['ephemeral_start_port']) -lt 255) {
        Throw "Ephemeral port range is incorrect. It must have at least 255 ports."
    }
    # Validate application port range
    $validRange = ($cfgCtxt['application_end_port'] - $cfgCtxt['application_start_port']) -ge 0
    if(!$validRange) {
        Throw "Application port range is not a valid range."
    }
    # Cache this as read-only global variable for the current hook,
    # in order to improve performance.
    Set-Variable -Name "ASF_CHARM_CFG" -Value $cfgCtxt -Scope Global -Option ReadOnly
    return $cfgCtxt
}

function Get-DotNetFrameworkInstaller {
    Write-JujuWarning "Trying to get .NET installer Juju resource"
    $installerPath = Start-ExecuteWithRetry -ScriptBlock {
        Get-JujuResource -Resource "dotnet-installer"
    } -RetryMessage "Failed to download .NET framework Juju resource. Retrying"
    return $installerPath
}

function Get-ASFZipPackage {
    Write-JujuWarning "Trying to get Azure Service Fabric zip package Juju resource"
    $zipPath = Start-ExecuteWithRetry -ScriptBlock {
        Get-JujuResource -Resource "asf-zip-package"
    } -RetryMessage "Failed to download Azure Service Fabric zip package. Retrying"
    return $zipPath
}

function Install-DotNetFramework {
    <#
    .SYNOPSIS
    Returns a boolean to indicate if a reboot is needed or not
    #>

    # Release codes for all the supported .NET frameworks (4.5.1 or higher)
    $supportedNetFrameworkReleases = @(
        378675, # .NET Framework 4.5.1 installed with Windows 8.1 or Windows Server 2012 R2
        378758, # .NET Framework 4.5.1 installed on Windows 8, Windows 7 SP1, or Windows Vista SP2
        379893, # .NET Framework 4.5.2
        393295, # .NET Framework 4.6 on Windows 10
        393297, # .NET Framework 4.6 on other OS versions
        394254, # .NET Framework 4.6.1 on Windows 10 November Update
        394271, # .NET Framework 4.6.1 on all other OS versions
        394802, # .NET Framework 4.6.2 on Windows 10 Anniversary Update
        394806  # .NET Framework 4.6.2 on all other OS versions
    )
    $item = Get-ItemProperty -Path "HKLM:\Software\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if($item -and ($item.Release -in $supportedNetFrameworkReleases)) {
        Write-JujuWarning "Supported .NET framework version by the charm already installed"
        return
    }
    $installerPath = Get-DotNetFrameworkInstaller
    Write-JujuWarning "Installing .NET framework"
    $p = Start-Process -Wait -PassThru -FilePath $installerPath `
                       -ArgumentList @('/q', '/norestart')
    if($p.ExitCode -ne 0) {
        if($p.ExitCode -eq 3010) {
            # 3010 -> Exit code that signals successful installation and a reboot is needed.
            return $true
        }
    }
    return $false
}

function Install-AzureServiceFabricPackage {
    if (Test-Path $ASF_PKG_DIR) {
        Remove-Item -Recurse -Force $ASF_PKG_DIR
    }
    Write-JujuWarning "Unzipping Azure Service Fabric zip package to $ASF_PKG_DIR"
    Expand-ZipArchive -ZipFile (Get-ASFZipPackage) -Destination $ASF_PKG_DIR
    # Extract DeploymentComponents
    Start-ExternalCommand -ScriptBlock { & "$ASF_PKG_DIR\DeploymentComponentsAutoextractor.exe" /E /Y /L $ASF_PKG_DIR }
}

function Get-PeerUnits {
    <#
    .SYNOPSIS
    Returns a list of peers that are ready to be clustered.
    #>

    if($Global:PEER_UNITS) {
        return $Global:PEER_UNITS
    }
    $peerUnits = [System.Collections.Generic.List[Hashtable]](New-Object "System.Collections.Generic.List[Hashtable]")
    $rids = Get-JujuRelationIds -Relation 'peer'
    foreach($rid in $rids) {
        $units = Get-JujuRelatedUnits -RelationId $rid
        foreach($unit in $units) {
            $data = Get-JujuRelation -RelationId $rid -Unit $unit
            if(!$data['computer-name']) {
                Write-JujuWarning "Unit $unit didn't set computer-name relation variable"
                continue
            }
            $peerUnits.Add(@{
                "node_name" = $data['computer-name']
                "ip_address" = $data['private-address']
            })
        }
    }
    # Include the current unit as well
    $peerUnits.Add(@{
        "node_name" = $COMPUTERNAME
        "ip_address" = Get-JujuUnitPrivateIP
    })
    # Cache this as read-only global variable for the current hook, in order to
    # improve performance.
    Set-Variable -Name "PEER_UNITS" -Value $peerUnits -Scope Global -Option ReadOnly
    return $peerUnits
}

function Disable-RemoteUAC {
    <#
    .SYNOPSIS
    Disable remote UAC filter, thus allowing remote users to access the
    local administrative shares using local administrators credentials.
    #>

    $registryNamespace = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $key = Get-ItemProperty -Path $registryNamespace
    # Make sure the 'LocalAccountTokenFilterPolicy' is set to 1 in order to
    # disable UAC for user connecting remote.
    if(!$key.LocalAccountTokenFilterPolicy) {
        New-ItemProperty -Path $registryNamespace -Name "LocalAccountTokenFilterPolicy" -Value 1
    } else {
        Set-ItemProperty -Path $registryNamespace -Name "LocalAccountTokenFilterPolicy" -Value 1
    }
    Restart-Service -Name "LanmanServer"
}

function Confirm-AzureServiceFabricPrerequisites {
    # RemoteRegistry service is a requirement for Azure Service Fabric. It
    # enables remote users to modify registry settings on your computer,
    # provided the remote users have the required permissions.
    Set-Service -Name "RemoteRegistry" -StartupType "Automatic"
    Start-Service -Name "RemoteRegistry"
    # Create required charm directories
    $dirs = @(
        $ASF_HOME_DIR,
        $DEFAULT_DIAGNOSTICS_STORE,
        $DEFAULT_FABRIC_LOG_ROOT,
        $DEFAULT_FABRIC_DATA_ROOT
    )
    foreach($dir in $dirs) {
        if(!(Test-Path -Path $dir)) {
            New-Item -ItemType Directory -Path $dir
        }
    }
}

function Open-CharmPorts {
    # Open SMB ports as this is required to create the Service Fabric cluster
    Enable-NetFirewallRule -Name "FPS-SMB-In-TCP"
    Enable-NetFirewallRule -Name "FPS-NB_Session-In-TCP"
    Disable-RemoteUAC
    $cfgCtxt = Get-CharmConfigContext
    Open-JujuPort -Port ("{0}/tcp" -f @($cfgCtxt['client_connection_endpoint_port']))
    Open-JujuPort -Port ("{0}/tcp" -f @($cfgCtxt['http_gateway_endpoint_port']))
    Open-JujuPort -Port ("{0}-{1}/tcp" -f @($cfgCtxt['application_start_port'], $cfgCtxt['application_end_port']))
}

function Get-RandomUserName {
    Param(
        [Parameter(Mandatory=$false)]
        [int]$Length=10
    )

    $lowerLetters = 97..122
    $name = [System.Collections.Generic.List[String]](New-object "System.Collections.Generic.List[String]")
    for($i=0; $i -lt $Length; $i++){
        $c = Get-Random -Input $lowerLetters
        $name.Add([char]$c)
    }
    $randomStr = [string]::join("", $name)
    return "asf-$randomStr"
}

function Get-ASFLocalAdminCredential {
    $leaderData = Get-LeaderData
    if(!$leaderData['charm-user-name'] -or !$leaderData['charm-user-password']) {
        return $null
    }
    $securePass = ConvertTo-SecureString -AsPlainText -Force $leaderData['charm-user-password']
    $creds = New-Object PSCredential($leaderData['charm-user-name'], $securePass)
    return $creds
}

function Get-ASFDomainAdminCredential {
    $adCtxt = Get-ActiveDirectoryContext
    if(!$adCtxt.Count -or !$adCtxt['adcredentials']) {
        return $null
    }
    $domainUser = "{0}\{1}" -f @($adCtxt['netbiosname'], $ASF_AD_ADMIN_NAME)
    Grant-PrivilegesOnDomainUser -Username $domainUser
    $creds = $adCtxt['adcredentials'] | Where-Object { $_.username -eq $domainUser }
    return $creds['pscredentials']
}

function Get-ASFCredential {
    $cfgCtxt = Get-CharmConfigContext
    switch($cfgCtxt['security_type']) {
        $WINDOWS_SECURITY_TYPE {
            $domainJoined = Start-JoinDomain
            $adCtxt = Get-ActiveDirectoryContext
            if($domainJoined -and $adCtxt['adcredentials']) {
                return (Get-ASFDomainAdminCredential)
            }
            # When cluster security type is set to Windows, ad-join relation is mandatory.
            Write-JujuWarning "Cluster security type is set to Windows. AD context is not ready yet"
            Set-JujuStatus -Status 'blocked' -Message 'Incomplete relation: ad-join'
            return $null
        }
        default {
            return (Get-ASFLocalAdminCredential)
        }
    }
}

function Get-NodesTypeName {
    <#
    .SYNOPSIS
    Returns the nodes type name of this deployment. This is equal to the charm
    name.
    #>

    $localUnitName = Get-JujuLocalUnit
    return $localUnitName.Split('/')[0]
}

function Get-ASFBaseClusterConfig {
    $cfgCtxt = Get-CharmConfigContext
    return @{
        "name" = $cfgCtxt['cluster_name']
        "clusterConfigurationVersion" = "1.0.0"
        "apiVersion" = "2015-01-01-alpha"
        "properties" = @{
            "reliabilityLevel" = $cfgCtxt['reliability_level']
            "diagnosticsStore" = @{
                "metadata" = "Local diagnostics store"
                "dataDeletionAgeInDays" = 7
                "storeType" = "FileShare"
                "IsEncrypted" = "false"
                "connectionstring" = $DEFAULT_DIAGNOSTICS_STORE
            }
            "nodeTypes" = @(
                @{
                    "name" = Get-NodesTypeName
                    "clientConnectionEndpointPort" = $cfgCtxt['client_connection_endpoint_port']
                    "clusterConnectionEndpointPort" = $cfgCtxt['cluster_connection_endpoint_port']
                    "leaseDriverEndpointPort" = $cfgCtxt['lease_driver_endpoint_port']
                    "serviceConnectionEndpointPort" = $cfgCtxt['service_connection_endpoint_port']
                    "httpGatewayEndpointPort" = $cfgCtxt['http_gateway_endpoint_port']
                    "applicationPorts" = @{
                        "startPort" = $cfgCtxt['application_start_port']
                        "endPort" = $cfgCtxt['application_end_port']
                    }
                    "ephemeralPorts" = @{
                        "startPort" = $cfgCtxt['ephemeral_start_port']
                        "endPort" = $cfgCtxt['ephemeral_end_port']
                    }
                    "isPrimary" = $true
                }
            )
            "fabricSettings" = @(
                @{
                    "name" = "Setup"
                    "parameters" = @(
                        @{
                            "name" = "FabricDataRoot"
                            "value" = $DEFAULT_FABRIC_DATA_ROOT
                        },
                        @{
                            "name" = "FabricLogRoot"
                            "value" = $DEFAULT_FABRIC_LOG_ROOT
                        }
                    )
                }
            )
        }
    }
}

# TODO(ibalutoiu): Add support for 'x509' certficates-based security type as well.
function Get-ASFClusterConfig {
    Param(
        [ValidateSet("Unsecure", "Windows", "x509")]
        [String]$ClusterSecurityType
    )

    $clusterConfig = Get-ASFBaseClusterConfig
    $peerUnits = Get-PeerUnits
    $nodes = [System.Collections.Generic.List[Hashtable]](New-Object "System.Collections.Generic.List[Hashtable]")
    switch($ClusterSecurityType) {
        "Unsecure" {
            foreach($unit in $peerUnits) {
                $nodes.Add(@{
                    "nodeName" = $unit['node_name']
                    "iPAddress" = $unit['ip_address']
                    "nodeTypeRef" = Get-NodesTypeName
                    "faultDomain" = ("fd:/{0}" -f @($cfgCtxt['fault_domain_name']))
                    "upgradeDomain" = $cfgCtxt['upgrade_domain_name']
                })
            }
            $clusterConfig['nodes'] = $nodes
            return $clusterConfig
        }
        "Windows" {
            $adCtxt = Get-ActiveDirectoryContext
            $adGroup = "{0}\{1}" -f @($adCtxt['domainName'], $ASF_AD_GROUP_NAME)
            $adUser = "{0}\{1}" -f @($adCtxt['domainName'], $ASF_AD_USER_NAME)
            $adAdmin = "{0}\{1}" -f @($adCtxt['domainName'], $ASF_AD_ADMIN_NAME)
            $clusterConfig['properties']['security'] = @{
                "ClusterCredentialType" = "Windows"
                "ServerCredentialType" = "Windows"
                "WindowsIdentities" = @{
                    "ClusterIdentity" = $adGroup
                    "ClientIdentities" = @(
                        @{
                            "Identity" = $adUser
                            "IsAdmin" = $false
                        },
                        @{
                            "Identity" = $adAdmin
                            "IsAdmin" = $true
                        }
                    )
                }
            }
            foreach($unit in $peerUnits) {
                $nodeFQDN = "{0}.{1}" -f @($unit['node_name'], $adCtxt['domainName'])
                $nodes.Add(@{
                    "nodeName" = $unit['node_name']
                    "iPAddress" = $nodeFQDN
                    "nodeTypeRef" = Get-NodesTypeName
                    "faultDomain" = ("fd:/{0}" -f @($cfgCtxt['fault_domain_name']))
                    "upgradeDomain" = $cfgCtxt['upgrade_domain_name']
                })
            }
            $clusterConfig['nodes'] = $nodes
            return $clusterConfig
        }
        default {
            Throw "$ClusterSecurityType cluster security type is not supported yet."
        }
    }
}

function Set-ASFClusterNodesAddresses {
    <#
    .SYNOPSIS
     Sets a leader variable with the list of the nodes addresses that
     successfully joined the cluster. This variable is used to check if the
     cluster is initialized, but also when trying to create a cluster connection.
     A cluster request can be addressed to any of the cluster nodes IP on
     the API port.
    #>

    $params = @{'ErrorAction' = 'Stop'}
    $cfgCtxt = Get-CharmConfigContext
    if($cfgCtxt['security_type'] -eq $WINDOWS_SECURITY_TYPE) {
        $params['WindowsCredential'] = $true
        $adCtxt = Get-ActiveDirectoryContext
        $nodeAddress = "{0}.{1}" -f @($COMPUTERNAME, $adCtxt['domainName'])
    } else {
        $nodeAddress = Get-JujuUnitPrivateIP
    }
    # Set 'cluster-nodes-addresses' to leader only for the moment.
    Set-LeaderData -Settings @{
        'cluster-nodes-addresses' = $nodeAddress
    }
    $params['ConnectionEndpoint'] = "{0}:{1}" -f @($nodeAddress, $cfgCtxt['client_connection_endpoint_port'])
    Write-JujuWarning "Trying to establish connection to cluster node address: $nodeAddress"
    Connect-ServiceFabricCluster @params | Out-Null
    $clusterNodes = Get-ServiceFabricNode -ErrorAction Stop
    Set-LeaderData -Settings @{
        'cluster-nodes-addresses' = ($clusterNodes.IpAddressOrFQDN -join ' ')
    }
}

function Get-ASFClusterNodesAddresses {
    # NOTE(ibalutoiu): The following leader variable is set only after
    #                  the ASF cluster was successfully initialized.
    #                  It represents a list of nodes addresses that are part
    #                  of the Azure Service Fabric cluster.
    $clusterNodesAddresses = Get-LeaderData -Attribute 'cluster-nodes-addresses'
    if($clusterNodesAddresses) {
        $nodesAddresses = $clusterNodesAddresses.Split()
    } else {
        $nodesAddresses = @()
    }
    return $nodesAddresses
}

function New-ASFCluster {
    [array]$clusterNodesAddresses = Get-ASFClusterNodesAddresses
    if($clusterNodesAddresses.Count) {
        Write-JujuWarning "Azure Service Fabric cluster is already created"
        Set-ASFClusterNodesAddresses
        return
    }
    [array]$peerUnits = Get-PeerUnits
    $cfgCtxt = Get-CharmConfigContext
    if($peerUnits.Count -lt $VALID_RELIABILITY_LEVELS[$cfgCtxt['reliability_level']]) {
        $msg = "Minimum {0} units are needed for {1} reliability level" -f @($VALID_RELIABILITY_LEVELS[$cfgCtxt['reliability_level']], $cfgCtxt['reliability_level'])
        Write-JujuWarning $msg
        Set-JujuStatus -Status "waiting" -Message $msg
        return
    }
    $clusterConfig = Get-ASFClusterConfig -ClusterSecurityType $cfgCtxt['security_type']
    $jsonConfigFile = Join-Path $ASF_HOME_DIR "ClusterConfig.json"
    $jsonClusterConfig = ConvertTo-Json -InputObject $clusterConfig -Depth 10
    Set-Content -Path $jsonConfigFile -Value $jsonClusterConfig
    Write-JujuWarning "Creating the Azure Service Fabric cluster"
    New-ServiceFabricCluster -ClusterConfigurationFilePath $jsonConfigFile `
                             -FabricRuntimePackagePath $ASF_RUNTIME_CAB_FILE_PATH `
                             -ErrorAction Stop
    Remove-Item -Path $jsonConfigFile -ErrorAction SilentlyContinue
    Set-ASFClusterNodesAddresses
    Set-JujuStatus -Status "active" -Message "Unit is ready"
}

function Join-ASFCluster {
    [array]$clusterNodesAddresses = Get-ASFClusterNodesAddresses
    if(!$clusterNodesAddresses.Count) {
        Write-JujuWarning "Azure Service Fabric cluster is not created yet"
        return
    }
    $params = @{'ErrorAction' = 'Stop'}
    $cfgCtxt = Get-CharmConfigContext
    if($cfgCtxt['security_type'] -eq $WINDOWS_SECURITY_TYPE) {
        $params['WindowsCredential'] = $true
    }
    foreach($address in $clusterNodesAddresses) {
        Write-JujuWarning "Trying to establish connection to cluster node address: $address"
        $params['ConnectionEndpoint'] = "{0}:{1}" -f @($address, $cfgCtxt['client_connection_endpoint_port'])
        try {
            Connect-ServiceFabricCluster @params | Out-Null
        } catch {
            Write-JujuWarning "Failed to establish connection to cluster node address: $address"
            $params['ConnectionEndpoint'] = $null
            continue
        }
        # Successfully created a cluster connection
        break
    }
    if(!$params['ConnectionEndpoint']) {
        Throw "Failed to create connection to any of the cluster nodes."
    }
    $node = Get-ServiceFabricNode -NodeName $COMPUTERNAME -ErrorAction SilentlyContinue
    if($node) {
        Write-JujuWarning "Current node is already in the Service Fabric cluster"
        Set-JujuStatus -Status "active" -Message "Unit is ready"
        return
    }
    Write-JujuWarning "Adding node $COMPUTERNAME to the Azure Service Fabric cluster"
    if($cfgCtxt['security_type'] -eq $WINDOWS_SECURITY_TYPE) {
        $adCtxt = Get-ActiveDirectoryContext 
        $nodeAddress = "{0}.{1}" -f @($COMPUTERNAME, $adCtxt['domainName'])
    } else {
        $nodeAddress = Get-JujuUnitPrivateIP
    }
    $jujuFD = "fd:/{0}" -f @($cfgCtxt['fault_domain_name'])
    Add-ServiceFabricNode -NodeName $COMPUTERNAME -NodeType (Get-NodesTypeName) `
                          -IpAddressOrFQDN $nodeAddress -UpgradeDomain $cfgCtxt['upgrade_domain_name'] `
                          -FaultDomain $jujuFD -FabricRuntimePackagePath $ASF_RUNTIME_CAB_FILE_PATH `
                          -Verbose -ErrorAction Stop
    $rids = Get-JujuRelationIds -Relation 'peer'
    foreach($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings @{'cluster-joined' = $true}
    }
    Set-JujuStatus -Status "active" -Message "Unit is ready"
}

function Remove-ASFClusterNode {
    <#
    .SYNOPSIS
    Removes the current node from the cluster
    #>

    [array]$clusterNodesAddresses = Get-ASFClusterNodesAddresses
    if(!$clusterNodesAddresses.Count) {
        Write-JujuWarning "Azure Service Fabric cluster is not created yet"
        return
    }
    # Remove the current node from the list of addresses as we don't want
    # to create a connection to the cluster node that we want to remove.
    $privateIP = Get-JujuUnitPrivateIP
    $clusterNodesAddresses = $clusterNodesAddresses | Where-Object { $_ -ne $privateIP }
    Write-JujuWarning "Removing $COMPUTERNAME from the Azure Service Fabric cluster"
    $params = @{
        'ErrorAction' = 'Stop'
    }
    $cfgCtxt = Get-CharmConfigContext
    if($cfgCtxt['security_type'] -eq $WINDOWS_SECURITY_TYPE) {
        $params['WindowsCredential'] = $true
    }
    foreach($address in $clusterNodesAddresses) {
        Write-JujuWarning "Trying to establish connection to cluster node address: $address"
        $params['ConnectionEndpoint'] = "{0}:{1}" -f @($address, $cfgCtxt['client_connection_endpoint_port'])
        try {
            Connect-ServiceFabricCluster @params | Out-Null
        } catch {
            Write-JujuWarning "Failed to establish connection to cluster node address: $address"
            $params['ConnectionEndpoint'] = $null
            continue
        }
        # Successfully created a cluster connection
        break
    }
    if(!$params['ConnectionEndpoint']) {
        Throw "Failed to create connection to any of the cluster nodes."
    }
    # Removes the current node from the cluster
    Remove-ServiceFabricNode -Verbose -ErrorAction Stop
}

function New-ASFLocalAdministrator {
    $leaderData = Get-LeaderData
    $userName = $leaderData['charm-user-name']
    $password = $leaderData['charm-user-password']
    if(!$userName -or !$password) {
        if(!(Confirm-Leader)) {
            Write-JujuWarning "Leader unit didn't set the charm user credentials"
            return
        }
        $userName = Get-RandomUserName
        $password = Get-RandomString -Length 10 -Weak
        Set-LeaderData -Settings @{
            'charm-user-name' = $userName
            'charm-user-password' = $password
        }
    }
    Add-WindowsUser -Username $userName -Password $password `
                    -Fullname $LOCAL_USER_FULL_NAME -Description $LOCAL_USER_DESCRIPTION
    Add-UserToLocalGroup -Username $userName -GroupSID $ADMINISTRATORS_GROUP_SID
    Grant-Privilege -User $userName -Grant "SeServiceLogonRight"
}

function Invoke-InstallHook {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true
    } catch {
        # No need to error out the hook if this fails.
        Write-JujuWarning "Failed to disable real-time monitoring"
    }
    # Set machine to use high performance settings.
    try {
        Set-PowerProfile -PowerProfile Performance
    } catch {
        # No need to error out the hook if this fails.
        Write-JujuWarning "Failed to set power scheme"
    }
    Start-TimeResync
    $renameReboot = Rename-JujuUnit
    $prereqReboot = Install-DotNetFramework
    if($renameReboot -or $prereqReboot) {
        Invoke-JujuReboot -Now
    }
    Confirm-AzureServiceFabricPrerequisites
    Install-AzureServiceFabricPackage
    New-ASFLocalAdministrator
    Open-CharmPorts
}

function Invoke-StopHook {
    $asfUserCreds = Get-ASFCredential
    if(!$asfUserCreds) {
        Write-JujuWarning "ASF user credentials are not ready yet"
        return
    }
    $scriptBlock = {
        $ErrorActionPreference = 'Stop'
        Import-Module JujuLogging
        try {
            Import-Module ASFHooks
            Remove-ASFClusterNode
        } catch {
            Write-HookTracebackToLog $_
            exit 1
        }
    }
    $exitCode = Start-ProcessAsUser -Credential $asfUserCreds -Command "$PShome\powershell.exe" `
                                    -Arguments @("-Command", $scriptBlock)
    if($exitCode) {
        Throw "Failed to run stop hook. Exit code: $exitCode"
    }
}

function Invoke-UpdateStatusHook {
    # TODO(ibalutoiu):
    # Remove all the cluster nodes that were forcedly removed.
    # Iterate over all the Juju units and all the cluster nodes, and remove the
    # cluster nodes that Juju is not aware of.
}

function Invoke-LeaderSettingsChangedHook {
    New-ASFLocalAdministrator
    $asfUserCreds = Get-ASFCredential
    if(!$asfUserCreds) {
        Write-JujuWarning "ASF user credentials are not ready yet"
        return
    }
    $scriptBlock = {
        $ErrorActionPreference = 'Stop'
        Import-Module JujuLogging
        try {
            Import-Module ASFHooks
            # Add the current node to the cluster if not yet added.
            Join-ASFCluster
        } catch {
            Write-HookTracebackToLog $_
            exit 1
        }
    }
    $exitCode = Start-ProcessAsUser -Credential $asfUserCreds -Command "$PShome\powershell.exe" `
                                    -Arguments @("-Command", $scriptBlock)
    if($exitCode) {
        Throw "Failed to run leader-settings-changed hook. Exit code: $exitCode"
    }
}

function Invoke-PeerRelationJoinedHook {
    $cfgCtxt = Get-CharmConfigContext
    $domainJoined = Start-JoinDomain
    if(($cfgCtxt['security_type'] -eq $WINDOWS_SECURITY_TYPE) -and !$domainJoined) {
        # When cluster security type is set to Windows, ad-join relation is mandatory.
        Write-JujuWarning "Cluster security type is set to Windows. AD context is not ready yet"
        Set-JujuStatus -Status 'blocked' -Message 'Incomplete relation: ad-join'
        return
    }
    $relationSettings = @{
        'computer-name' = $COMPUTERNAME
    }
    $rids = Get-JujuRelationIds -Relation 'peer'
    foreach($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $relationSettings
    }
}

function Invoke-PeerRelationChangedHook {
    $asfUserCreds = Get-ASFCredential
    if(!$asfUserCreds) {
        Write-JujuWarning "ASF user credentials are not ready yet"
        return
    }
    $scriptBlock = {
        $ErrorActionPreference = 'Stop'
        Import-Module JujuLogging
        try {
            Import-Module ASFHooks
            Import-Module JujuHooks
            if(Confirm-Leader) {
                New-ASFCluster
            }
            # Add the current node to the cluster if not yet added.
            Join-ASFCluster
        } catch {
            Write-HookTracebackToLog $_
            exit 1
        }
    }
    $exitCode = Start-ProcessAsUser -Credential $asfUserCreds -Command "$PShome\powershell.exe" `
                                    -Arguments @("-Command", $scriptBlock)
    if($exitCode) {
        Throw "Failed to run peer-relation-changed hook. Exit code: $exitCode"
    }
}

function Invoke-ADJoinRelationJoinedHook {
    $settings = @{
        'computername' = $COMPUTERNAME
    }
    $adUsers = @{
        $ASF_AD_USER_NAME = @("Users")
        $ASF_AD_ADMIN_NAME = @("Users")
    }
    $settings['users'] = Get-MarshaledObject $adUsers
    $settings['computer-group'] = $ASF_AD_GROUP_NAME
    $rids = Get-JujuRelationIds -Relation "ad-join"
    foreach ($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $settings
    }
}

function Invoke-ADJoinRelationChangedHook {
    $domainJoined = Start-JoinDomain
    if($domainJoined) {
        Invoke-PeerRelationJoinedHook
        Invoke-PeerRelationChangedHook
    }
}

function Invoke-ReverseProxyJoinedHook {
    $cfgCtxt = Get-CharmConfigContext
    $apiPort = $cfgCtxt['client_connection_endpoint_port']
    $guiPort = $cfgCtxt['http_gateway_endpoint_port']
    $privateIP = Get-JujuUnitPrivateIP
    $relationSettings = @{
        'services' = "
            - { service_name: AzureServiceFabricGUI,
                service_host: 0.0.0.0,
                service_port: '$guiPort',
                service_options: [balance leastconn, cookie SRVNAME insert],
                servers: [[$COMPUTERNAME, $privateIP, $guiPort, 'maxconn 100 cookie S{i} check']] }
            - { service_name: AzureServiceFabricAPI,
                service_host: 0.0.0.0,
                service_port: '$apiPort',
                service_options: [balance leastconn, cookie SRVNAME insert],
                servers: [[$COMPUTERNAME, $privateIP, $apiPort, 'maxconn 100 cookie S{i} check']] }
        "
    }
    $rids = Get-JujuRelationIds 'reverseproxy'
    foreach ($rid in $rids) {
        Set-JujuRelation -Settings $relationSettings -RelationId $rid
    }
}
