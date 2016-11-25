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
$CHARM_USER_FULL_NAME = "ASF Juju User"
$CHARM_USER_DESCRIPTION = "Local administrator user used by the Juju charm to create and manage the Azure Service Fabric cluster"

$DEFAULT_FABRIC_LOG_ROOT = Join-Path $ASF_HOME_DIR "Log"
$DEFAULT_FABRIC_DATA_ROOT = Join-Path $ASF_HOME_DIR "FabricDataRoot"
$DEFAULT_DIAGNOSTICS_STORE = Join-Path $ASF_HOME_DIR "DiagnosticsStore"

$COMPUTERNAME = [System.Net.Dns]::GetHostName()
# Dictionary with the default config option values, which are used in case the
# charm config options are empty.
$CHARM_CONFIGS = @{
    'cluster-name'                     = 'JujuServiceFabric'
    'security-type'                    = 'Unsecure'
    'reliability-level'                = 'Bronze'
    'node-type-name'                   = 'JujuNodeType'
    'fault-domain-name'                = 'JujuFD'
    'upgrade-domain-name'              = 'JujuUD'
    'client-connection-endpoint-port'  = 19000
    'cluster-connection-endpoint-port' = 19001
    'lease-driver-endpoint-port'       = 19002
    'service-connection-endpoint-port' = 19003
    'http-gateway-endpoint-port'       = 19080
    'ephemeral-start-port'             = 20606
    'ephemeral-end-port'               = 20861
    'application-start-port'           = 20575
    'application-end-port'             = 20605

}
# Mapping between reliability levels and the minimum number of primary nodes
# required to achieve it.
$VALID_RELIABILITY_LEVELS = @{
    "Bronze"   = 3
    "Silver"   = 5
    "Gold"     = 7
    "Platinum" = 9
}
$VALID_SECURITY_TYPES = @("Unsecure", "Windows", "x509")
# Release codes for all the supported .NET frameworks (4.5.1 or higher)
$SUPPORTED_NET_FRAMEWORK_RELEASES = @(
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


function Get-CharmConfigContext {
    $cfgCtxt = @{}
    $cfg = Get-JujuCharmConfig

    foreach($key in $CHARM_CONFIGS.Keys) {
        if(!$cfg[$key]) {
            $cfgCtxt[($key -replace '-', '_')] = $CHARM_CONFIGS[$key]
        } else {
            $cfgCtxt[($key -replace '-', '_')] = $cfg[$key]
        }
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

    $item = Get-ItemProperty -Path "HKLM:\Software\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if($item -and ($item.Release -in $SUPPORTED_NET_FRAMEWORK_RELEASES)) {
        Write-JujuWarning "Supported .NET framework version by the charm already installed"
        return
    }

    $installerPath = Get-DotNetFrameworkInstaller

    Write-JujuWarning "Installing .NET framework"

    $p = Start-Process -Wait -PassThru -FilePath $installerPath `
                       -ArgumentList @('/q', '/norestart')
    if($p.ExitCode -ne 0) {
        if($p.ExitCode -eq 3010) {
            # Installer finished successfully and a reboot is needed.
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

    return $peerUnits
}

function Disable-RemoteUAC {
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
    Open-JujuPort -Port "445/tcp"
    Disable-RemoteUAC

    $cfgCtxt = Get-CharmConfigContext
    Open-JujuPort -Port ("{0}/tcp" -f @($cfgCtxt['client_connection_endpoint_port']))
    Open-JujuPort -Port ("{0}/tcp" -f @($cfgCtxt['cluster_connection_endpoint_port']))
    Open-JujuPort -Port ("{0}/tcp" -f @($cfgCtxt['lease_driver_endpoint_port']))
    Open-JujuPort -Port ("{0}/tcp" -f @($cfgCtxt['service_connection_endpoint_port']))
    Open-JujuPort -Port ("{0}/tcp" -f @($cfgCtxt['http_gateway_endpoint_port']))
    Open-JujuPort -Port ("{0}-{1}/tcp" -f @($cfgCtxt['ephemeral_start_port'], $cfgCtxt['ephemeral_end_port']))
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

    return [string]::join("", $name)
}

function Get-ASFUserCredential {
    $leaderData = Get-LeaderData
    if(!$leaderData['charm-user-name'] -or !$leaderData['charm-user-password']) {
        return $null
    }

    $securePass = ConvertTo-SecureString -AsPlainText -Force $leaderData['charm-user-password']
    $creds = New-Object PSCredential($leaderData['charm-user-name'], $securePass)

    return $creds
}

function Get-UnsecureMultiMachineJsonClusterConfig {
    Param(
        [Parameter(Mandatory=$true)]
        [Hashtable[]]$PeerUnits
    )

    $cfgCtxt = Get-CharmConfigContext

    $nodes = [System.Collections.Generic.List[Hashtable]](New-Object "System.Collections.Generic.List[Hashtable]")
    foreach($unit in $PeerUnits) {
        $nodes.Add(@{
            "nodeName" = $unit['node_name']
            "iPAddress" = $unit['ip_address']
            "nodeTypeRef" = $cfgCtxt['node_type_name']
            "faultDomain" = ("fd:/{0}" -f @($cfgCtxt['fault_domain_name']))
            "upgradeDomain" = $cfgCtxt['upgrade_domain_name']
        })
    }
    $nodes.Add(@{
        "nodeName" = $COMPUTERNAME
        "iPAddress" = Get-JujuUnitPrivateIP
        "nodeTypeRef" = $cfgCtxt['node_type_name']
        "faultDomain" = ("fd:/{0}" -f @($cfgCtxt['fault_domain_name']))
        "upgradeDomain" = $cfgCtxt['upgrade_domain_name']
    })

    return @{
        "name" = $cfgCtxt['cluster_name']
        "clusterConfigurationVersion" = "1.0.0"
        "apiVersion" = "2015-01-01-alpha"
        "nodes" = $nodes
        "properties" = @{
            "reliabilityLevel" = "Bronze"
            "diagnosticsStore" = @{
                "metadata" = "Local diagnostics store"
                "dataDeletionAgeInDays" = 7
                "storeType" = "FileShare"
                "IsEncrypted" = "false"
                "connectionstring" = $DEFAULT_DIAGNOSTICS_STORE
            }
            "nodeTypes" = @(
                @{
                    "name" = $cfgCtxt['node_type_name']
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

# TODO(ibalutoiu): Add support for other cluster configurations later on.
#                  Only unsecured is supported at the moment.
function Get-ASFJsonClusterConfig {
    Param(
        [ValidateSet("Unsecure", "Windows", "x509")]
        [String]$ClusterSecurityType,
        [Parameter(Mandatory=$true)]
        [Hashtable[]]$PeerUnits
    )

    switch($ClusterSecurityType) {
        "Unsecure" {
            return (Get-UnsecureMultiMachineJsonClusterConfig -PeerUnits $PeerUnits)
        }
        default {
            Throw "$ClusterSecurityType cluster security type is not supported yet."
        }
    }
}

function Get-IsASFClusterInstalled {
    # NOTE(ibalutoiu): The following leader variable is set only after
    #                  the ASF cluster was successfully initialized.
    return (Get-LeaderData -Attribute 'cluster-installed')
}

function Get-PeerContext {
    $required = @{
        "private-address" = $null
    }

    return (Get-JujuRelationContext -Relation "peer" -RequiredContext $required)
}

function Get-IsNodeInCluster {
    if(!(Get-IsASFClusterInstalled)) {
        Write-JujuWarning "Azure Service Fabric cluster is not created yet."
        return $false
    }

    $peerCtxt = Get-PeerContext
    if(!$peerCtxt.Count) {
        Write-JujuWarning "Peer context is not ready yet"
        return $false
    }

    # NOTE(ibalutoiu):
    # If DeploymentComponents is not added in PATH, the Azure Service Provider
    # PowerShell cmdlets complain because they can't find the 'FabricCommon.dll'
    $env:PATH += ";$ASF_PKG_DIR\DeploymentComponents"
    Import-Module "$ASF_PKG_DIR\DeploymentComponents\ServiceFabric.psd1" | Out-Null

    $cfgCtxt = Get-CharmConfigContext
    $connectionEndpoint = "{0}:{1}" -f @($peerCtxt['private-address'], $cfgCtxt['client_connection_endpoint_port'])
    Connect-ServiceFabricCluster -ConnectionEndpoint $connectionEndpoint | Out-Null

    $node = Get-ServiceFabricNode -NodeName $COMPUTERNAME -ErrorAction SilentlyContinue

    return ($node -ne $null)
}

function New-ASFCluster {
    # This is set only after the cluster is created
    if(Get-IsASFClusterInstalled) {
        Write-JujuWarning "Azure Service Fabric cluster is already created"

        Set-LeaderData -Settings @{'cluster-installed' = Get-JujuUnitPrivateIP}
        return
    }

    [array]$peerUnits = Get-PeerUnits
    $cfgCtxt = Get-CharmConfigContext
    if($peerUnits.Count -lt ($VALID_RELIABILITY_LEVELS[$cfgCtxt['reliability_level']] - 1)) {
        $msg = "Minimum {0} units are needed for {1} reliability level" -f @($VALID_RELIABILITY_LEVELS[$cfgCtxt['reliability_level']], $cfgCtxt['reliability_level'])
        Set-JujuStatus -Status "waiting" -Message $msg
        return
    }

    $clusterConfig = Get-ASFJsonClusterConfig -ClusterSecurityType $cfgCtxt['security_type'] -PeerUnits $peerUnits

    $jsonConfigFile = Join-Path $ASF_HOME_DIR "ClusterConfig.json"
    $jsonClusterConfig = ConvertTo-Json -InputObject $clusterConfig -Depth 10
    Set-Content -Path $jsonConfigFile -Value $jsonClusterConfig

    Write-JujuWarning "Creating the Azure Service Fabric cluster"

    $savedPath = $env:PATH
    Start-ExternalCommand -ScriptBlock {
        # NOTE(ibalutoiu):
        # The following script to create the Service Fabric Cluster from the package
        # resets the path. Thus we save the path before calling it and restore after
        # the call was finished.
        & $ASF_PKG_DIR\CreateServiceFabricCluster.ps1 -ClusterConfigFilePath $jsonConfigFile -AcceptEULA
    }
    $env:PATH = $savedPath

    Remove-Item -Path $jsonConfigFile

    Set-LeaderData -Settings @{'cluster-installed' = Get-JujuUnitPrivateIP}
}

function Join-ASFCluster {
    if(!(Get-IsASFClusterInstalled)) {
        Write-JujuWarning "Azure Service Fabric cluster is not created yet"
        return
    }

    if(Get-IsNodeInCluster) {
        Write-JujuWarning "Current node is already in the Service Fabric cluster"

        Set-JujuStatus -Status "active" -Message "Unit is ready"
        return
    }

    $peerCtxt = Get-PeerContext
    if(!$peerCtxt.Count) {
        Write-JujuWarning "Peer context is not ready yet"
        return
    }

    $cfgCtxt = Get-CharmConfigContext
    $privateIP = Get-JujuUnitPrivateIP
    $jujuFD = "fd:/{0}" -f @($cfgCtxt['fault_domain_name'])
    $connectionEndpoint = "{0}:{1}" -f @($peerCtxt['private-address'], $cfgCtxt['client_connection_endpoint_port'])

    Write-JujuWarning "Adding node $COMPUTERNAME to the Azure Service Fabric cluster"

    $savedPath = $env:PATH
    Start-ExternalCommand {
        & $ASF_PKG_DIR\AddNode.ps1 -NodeName $COMPUTERNAME -NodeType $cfgCtxt['node_type_name'] -NodeIPAddressorFQDN $privateIP `
                                   -UpgradeDomain $cfgCtxt['upgrade_domain_name'] -FaultDomain $jujuFD `
                                   -ExistingClientConnectionEndpoint $connectionEndpoint -AcceptEULA
    }
    $env:PATH = $savedPath

    Set-JujuStatus -Status "active" -Message "Unit is ready"
}

function New-ASFLocalAdministrator {
    $leaderData = Get-LeaderData
    if(!$leaderData['charm-user-name'] -or !$leaderData['charm-user-password']) {
        if(!(Confirm-Leader)) {
            Write-JujuWarning "Leader unit didn't set the charm user credentials"
            return
        }
        $userName = "asf-{0}" -f @(Get-RandomUserName)
        $password = Get-RandomString -Length 10 -Weak
        Set-LeaderData -Settings @{
            'charm-user-name' = $userName
            'charm-user-password' = $password
        }
    } else {
        $userName = $leaderData['charm-user-name']
        $password = $leaderData['charm-user-password']
    }

    Add-WindowsUser -Username $userName -Password $password `
                    -Fullname $CHARM_USER_FULL_NAME -Description $CHARM_USER_DESCRIPTION

    $administratorsGroupSID = "S-1-5-32-544"
    Add-UserToLocalGroup -Username $userName -GroupSID $administratorsGroupSID
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
    if(!(Get-IsASFClusterInstalled)) {
        Write-JujuWarning "Azure Service Fabric cluster is not created yet"
        return
    }

    $peerCtxt = Get-PeerContext
    if(!$peerCtxt.Count) {
        Write-JujuWarning "Peer context is not ready yet"
        return
    }

    Write-JujuWarning "Removing $COMPUTERNAME from the Azure Service Fabric cluster"

    $env:PATH += ";$ASF_PKG_DIR\DeploymentComponents"
    Import-Module "$ASF_PKG_DIR\DeploymentComponents\ServiceFabric.psd1"

    $cfgCtxt = Get-CharmConfigContext
    $connectionEndpoint = "{0}:{1}" -f @($peerCtxt['private-address'], $cfgCtxt['client_connection_endpoint_port'])
    Connect-ServiceFabricCluster -ConnectionEndpoint $connectionEndpoint

    $savedPath = $env:PATH
    Start-ExternalCommand {
        & $ASF_PKG_DIR\RemoveNode.ps1 -ExistingClientConnectionEndpoint $connectionEndpoint
    }
    $env:PATH = $savedPath
}

function Invoke-LeaderSettingsChangedHook {
    New-ASFLocalAdministrator

    # Add the current node to the cluster if not yet added.
    Join-ASFCluster
}

function Invoke-PeerRelationJoinedHook {
    $relationSettings = @{
        'computer-name' = $COMPUTERNAME
    }

    $rids = Get-JujuRelationIds -Relation 'peer'
    foreach($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $relationSettings
    }
}

function Invoke-PeerRelationChangedHook {
    if(Confirm-Leader) {
        $scriptBlock = {
            Import-Module ASFHooks
            New-ASFCluster
        }
        $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" -Arguments @("-Command", $scriptBlock) `
                                        -Credential (Get-ASFUserCredential) -LoadUserProfile $false
        if($exitCode) {
            Throw "Failed to create the Azure Service Fabric cluster. Exit code: $exitCode"
        }
    }

    # Add the current node to the cluster if not yet added.
    Join-ASFCluster
}

function Invoke-WebsiteRelationJoinedHook {
    $cfgCtxt = Get-CharmConfigContext
    $relationSettings = @{
        "hostname" = Get-JujuUnitPrivateIP
        "port" = $cfgCtxt['http_gateway_endpoint_port']
    }

    $rids = Get-JujuRelationIds 'website'
    foreach ($rid in $rids) {
        Set-JujuRelation -Settings $relationSettings -RelationId $rid
    }
}
