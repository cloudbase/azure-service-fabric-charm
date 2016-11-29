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

$ErrorActionPreference = 'Stop'

Import-Module JujuLogging


try {
    Import-Module ADCharmUtils
    Import-Module JujuHooks

    $adCtxt = Get-ActiveDirectoryContext
    if (!$adCtxt["adcredentials"]) {
        Write-JujuWarning "AD credentials are not ready yet"
        exit 0
    }

    $actionSettings = @{
        'domain' = $adCtxt['netbiosname']
    }
    foreach ($user in $adCtxt["adcredentials"]) {
        $actionSettings[$user["username"].Split("\")[1]] = $user["password"]
    }

    Set-JujuAction -Settings $actionSettings
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
