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

$ErrorActionPreference = "Stop"

Import-Module JujuLogging


try {
    Import-Module ASFHooks
    Import-Module JujuHooks
    Import-Module JujuWindowsUtils

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
            Open-WindowsFirewallPorts
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
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
