[CmdletBinding()]
Param
(
    [string]
    $Product = '1234_CostOptimization',

    [array]
    $SubscriptionIds = @(),

    [string]
    $ProductVersion = '1.0.0',

    # <--- AzAPICall related parameters #consult the AzAPICall GitHub repository for details https://aka.ms/AzAPICall (https://www.powershellgallery.com/packages/AzAPICall)
    [string]
    $AzAPICallVersion = '1.2.1',

    [switch]
    $DebugAzAPICall,

    [string]
    $SubscriptionId4AzContext = 'undefined',
    # --->

    [string]
    $OutputPath = 'output',

    [int]
    $AzureConsumptionPeriod = 10,

    [int]
    $ThrottleLimit = 10,

    [string]
    [parameter(ValueFromPipeline)][ValidateSet(';', ',')][string]$CsvDelimiter = ';',

    [string]
    $DirectorySeparatorChar = [IO.Path]::DirectorySeparatorChar,

    [ValidateScript({ $_ -cin [cultureinfo]::GetCultures('allCultures').Name })]
    $NumberCulture = 'en-US'
)

$Error.clear()
$ErrorActionPreference = 'Stop'
#removeNoise
$ProgressPreference = 'SilentlyContinue'

$azureConsumptionStartDate = ((Get-Date).AddDays( - ($($AzureConsumptionPeriod)))).ToString('yyyy-MM-dd')
$azureConsumptionEndDate = ((Get-Date).AddDays(-1)).ToString('yyyy-MM-dd')
$arrayOrphanedResources = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$fileName = $Product

#early validation
if ($SubscriptionIds.Count -eq 0) {
    Write-Host 'No SubscriptionIds provided' -ForegroundColor Red
    Throw 'Error - check the last console output for details'
}
else {
    foreach ($subscriptionId in $SubscriptionIds) {
        #regex valid guid
        if ($subscriptionId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            Write-Host "Invalid SubscriptionId '$subscriptionId' - must be GUID" -ForegroundColor Red
            Throw 'Error - check the last console output for details'
        }
    }
}

#region functions
function setOutput {
    if (-not [IO.Path]::IsPathRooted($outputPath)) {
        $outputPath = Join-Path -Path (Get-Location).Path -ChildPath $outputPath
    }
    $outputPath = Join-Path -Path $outputPath -ChildPath '.'
    $script:outputPath = [IO.Path]::GetFullPath($outputPath)
    if (-not (Test-Path $outputPath)) {
        Write-Host "path $outputPath does not exist - please create it!" -ForegroundColor Red
        Throw 'Error - check the last console output for details'
    }
    else {
        Write-Host "Output/Files will be created in path '$outputPath'"
    }
}

function verifyModules3rd {
    [CmdletBinding()]Param(
        [object]$modules
    )

    foreach ($module in $modules) {
        $moduleVersion = $module.ModuleVersion

        if ($moduleVersion) {
            Write-Host "Verify '$($module.ModuleName)' version '$moduleVersion'"
        }
        else {
            Write-Host "Verify '$($module.ModuleName)' (latest)"
        }

        $maxRetry = 3
        $tryCount = 0
        do {
            $tryCount++
            if ($tryCount -gt $maxRetry) {
                Write-Host " Managing '$($module.ModuleName)' failed (tried $($tryCount - 1)x)"
                throw " Managing '$($module.ModuleName)' failed"
            }

            $installModuleSuccess = $false
            try {
                if (-not $moduleVersion) {
                    Write-Host '  Check latest module version'
                    try {
                        $moduleVersion = (Find-Module -Name $($module.ModuleName)).Version
                        Write-Host " $($module.ModuleName) Latest module version: $moduleVersion"
                    }
                    catch {
                        Write-Host " $($module.ModuleName) - Check latest module version failed"
                        throw " $($module.ModuleName) - Check latest module version failed"
                    }
                }

                if (-not $installModuleSuccess) {
                    try {
                        $moduleVersionLoaded = (Get-InstalledModule -Name $($module.ModuleName)).Version
                        if ([System.Version]$moduleVersionLoaded -eq [System.Version]$moduleVersion) {
                            $installModuleSuccess = $true
                        }
                        else {
                            Write-Host " $($module.ModuleName) - Deviating module version '$moduleVersionLoaded'"
                            if ([System.Version]$moduleVersionLoaded -gt [System.Version]$moduleVersion) {
                                if (($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) -or $env:GITHUB_ACTIONS) {
                                    #AzDO or GH
                                    throw " $($module.ModuleName) - Deviating module version $moduleVersionLoaded"
                                }
                                else {
                                    Write-Host " Current module version '$moduleVersionLoaded' greater than the minimum required version '$moduleVersion' -> tolerated" -ForegroundColor Yellow
                                    $installModuleSuccess = $true
                                }
                            }
                            else {
                                Write-Host " Current module version '$moduleVersionLoaded' lower than the minimum required version '$moduleVersion' -> failed"
                                throw " $($module.ModuleName) - Deviating module version $moduleVersionLoaded"
                            }
                        }
                    }
                    catch {
                        throw
                    }
                }
            }
            catch {
                Write-Host " '$($module.ModuleName) $moduleVersion' not installed"
                if (($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) -or $env:GITHUB_ACTIONS) {
                    Write-Host " Installing $($module.ModuleName) module ($($moduleVersion))"
                    $installAzAPICallModuleTryCounter = 0
                    do {
                        $installAzAPICallModuleTryCounter++
                        try {
                            $params = @{
                                Name            = "$($module.ModuleName)"
                                Force           = $true
                                RequiredVersion = $moduleVersion
                                ErrorAction     = 'Stop'
                            }
                            Install-Module @params
                            $installAzAPICallModuleSuccess = $true
                            Write-Host "  Try#$($installAzAPICallModuleTryCounter) Installing '$($module.ModuleName)' module ($($moduleVersion)) succeeded"
                        }
                        catch {
                            Write-Host "  Try#$($installAzAPICallModuleTryCounter) Installing '$($module.ModuleName)' module ($($moduleVersion)) failed - sleep $($installAzAPICallModuleTryCounter) seconds"
                            Start-Sleep -Seconds $installAzAPICallModuleTryCounter
                            $installAzAPICallModuleSuccess = $false
                        }
                    }
                    until($installAzAPICallModuleTryCounter -gt 10 -or $installAzAPICallModuleSuccess)
                    if (-not $installAzAPICallModuleSuccess) {
                        throw " Installing '$($module.ModuleName)' module ($($moduleVersion)) failed"
                    }

                }
                else {
                    do {
                        $installModuleUserChoice = $null
                        $installModuleUserChoice = Read-Host " Do you want to install $($module.ModuleName) module ($($moduleVersion)) from the PowerShell Gallery? (y/n)"
                        if ($installModuleUserChoice -eq 'y') {
                            try {
                                Install-Module -Name $module.ModuleName -RequiredVersion $moduleVersion -Force -ErrorAction Stop
                                try {
                                    Import-Module -Name $module.ModuleName -RequiredVersion $moduleVersion -Force -ErrorAction Stop
                                }
                                catch {
                                    throw " 'Import-Module -Name $($module.ModuleName) -RequiredVersion $moduleVersion -Force' failed"
                                }
                            }
                            catch {
                                throw " 'Install-Module -Name $($module.ModuleName) -RequiredVersion $moduleVersion' failed"
                            }
                        }
                        elseif ($installModuleUserChoice -eq 'n') {
                            Write-Host " $($module.ModuleName) module is required, please visit https://aka.ms/$($module.ModuleProductName) or https://www.powershellgallery.com/packages/$($module.ModuleProductName)"
                            throw " $($module.ModuleName) module is required"
                        }
                        else {
                            Write-Host " Accepted input 'y' or 'n'; start over.."
                        }
                    }
                    until ($installModuleUserChoice -eq 'y')
                }
            }
        }
        until ($installModuleSuccess)
        Write-Host " Verify '$($module.ModuleName)' version '$moduleVersion' succeeded" -ForegroundColor Green
    }
}

function addHtParameters {
    Write-Host "Add '$Product' htParameters"

    $azAPICallConf['htParameters'] += [ordered]@{
        ThrottleLimit = $ThrottleLimit
    }
    Write-Host 'htParameters:'
    $azAPICallConf['htParameters'] | Format-Table -AutoSize | Out-String
    Write-Host 'Add '$Product' htParameters succeeded' -ForegroundColor Green
}

function getOrphanedResources {

    Param
    (
        [Parameter(Mandatory = $True)]
        $subsToProcessInCustomDataCollection,

        [Parameter(Mandatory = $True)]
        $arrayOrphanedResources
    )
    $start = Get-Date
    Write-Host 'Getting orphaned/unused resources (ARG)'

    #Todo - collect creation/update timestamps for resources

    #region queries
    $queries = [System.Collections.ArrayList]@()
    $intent = 'cost savings - stopped but not deallocated VM'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.compute/virtualmachines'
            query     = @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where properties.extended.instanceView.powerState.code =~ 'PowerState/stopped'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'clean up'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.resources/subscriptions/resourceGroups'
            query     = @"
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions/resourceGroups'
| extend rgAndSub = strcat(resourceGroup, '--', subscriptionId)
| join kind=leftouter (
    resources
    | extend rgAndSub = strcat(resourceGroup, '--', subscriptionId)
    | summarize count() by rgAndSub
) on rgAndSub
| where isnull(count_)
| order by id
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/networkSecurityGroups'
            query     = @"
resources
| where type =~ 'microsoft.network/networkSecurityGroups'
| where isnull(properties.networkInterfaces) and isnull(properties.subnets)
| order by id
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/routeTables'
            query     = @"
resources
| where type =~ 'microsoft.network/routeTables'
| where isnull(properties.subnets)
| order by id
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/networkInterfaces'
            query     = @"
resources
| where type =~ 'microsoft.network/networkInterfaces'
| where isnull(properties.privateEndpoint) and isnull(properties.privateLinkService) and properties.hostedWorkloads == '[]' and properties !has 'virtualmachine'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.compute/disks'
            query     = @"
resources
| where type has 'microsoft.compute/disks'
| where isempty(managedBy) or properties.diskState =~ 'unattached' and not(name endswith '-ASRReplica' or name startswith 'ms-asr-' or name startswith 'asrseeddisk-')
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/publicIpAddresses'
            query     = @"
resources | where type =~ 'microsoft.network/publicIpAddresses'
| where properties.ipConfiguration == '' and properties.natGateway == '' and properties.publicIPPrefix == '' and properties.publicIPAllocationMethod =~ 'Static'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/publicIpAddresses'
            query     = @"
resources | where type =~ 'microsoft.network/publicIpAddresses'
| where properties.ipConfiguration == '' and properties.natGateway == '' and properties.publicIPPrefix == '' and properties.publicIPAllocationMethod =~ 'Dynamic'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.compute/availabilitySets'
            query     = @"
resources
| where type =~ 'microsoft.compute/availabilitySets'
| where properties.virtualMachines == '[]'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/loadBalancers'
            query     = @"
resources
| where type =~ 'microsoft.network/loadBalancers'
| where properties.backendAddressPools == '[]'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/applicationGateways'
            query     = @"
resources
| where type =~ 'microsoft.network/applicationgateways'
| extend backendPoolsCount = array_length(properties.backendAddressPools),SKUName= tostring(properties.sku.name), SKUTier= tostring(properties.sku.tier),SKUCapacity=properties.sku.capacity,backendPools=properties.backendAddressPools , AppGwId = tostring(id)
| project type, AppGwId, resourceGroup, location, subscriptionId, tags, name, SKUName, SKUTier, SKUCapacity
| join (
    resources
    | where type =~ 'microsoft.network/applicationgateways'
    | mvexpand backendPools = properties.backendAddressPools
    | extend backendIPCount = array_length(backendPools.properties.backendIPConfigurations)
    | extend backendAddressesCount = array_length(backendPools.properties.backendAddresses)
    | extend backendPoolName  = backendPools.properties.backendAddressPools.name
    | extend AppGwId = tostring(id)
    | summarize backendIPCount = sum(backendIPCount) ,backendAddressesCount=sum(backendAddressesCount) by AppGwId
) on AppGwId
| project-away AppGwId1
| where  (backendIPCount == 0 or isempty(backendIPCount)) and (backendAddressesCount == 0 or isempty(backendAddressesCount))
| project type, subscriptionId, Resource=AppGwId, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.web/serverfarms'
            query     = @"
resources
| where type =~ 'microsoft.web/serverfarms'
| where properties.numberOfSites == 0 and sku.tier !~ 'Free'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.web/serverfarms'
            query     = @"
resources
| where type =~ 'microsoft.web/serverfarms'
| where properties.numberOfSites == 0 and sku.tier =~ 'Free'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    #new
    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.sql/servers/elasticpools'
            query     = @"
resources
| where type =~ 'microsoft.sql/servers/elasticpools'
| project type, elasticPoolId = tolower(id), Resource = id, resourceGroup, location, subscriptionId, tags, properties, Details = pack_all(), Intent='$intent'
| join kind=leftouter (
    resources
    | where type =~ 'Microsoft.Sql/servers/databases'
    | project id, properties
    | extend elasticPoolId = tolower(properties.elasticPoolId)
) on elasticPoolId
| summarize databaseCount = countif(id != '') by type, Resource, subscriptionId, Intent
| where databaseCount == 0
| project-away databaseCount
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/trafficmanagerprofiles'
            query     = @"
resources
| where type =~ 'microsoft.network/trafficmanagerprofiles'
| where properties.endpoints == '[]'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/virtualnetworks'
            query     = @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| where properties.subnets == '[]'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/virtualnetworks/subnets'
            query     = @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| extend subnet = properties.subnets
| mv-expand subnet
| extend ipConfigurations = subnet.properties.ipConfigurations
| extend delegations = subnet.properties.delegations
| where isnull(ipConfigurations) and delegations == '[]'
| order by tostring(subnet.id)
| project type, subscriptionId, Resource=(subnet.id), Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/natgateways'
            query     = @"
resources
| where type =~ 'microsoft.network/natgateways'
| where isnull(properties.subnets)
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/ipgroups'
            query     = @"
resources
| where type =~ 'microsoft.network/ipgroups'
| where properties.firewalls == '[]' and properties.firewallPolicies == '[]'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/privatednszones'
            query     = @"
resources
| where type =~ 'microsoft.network/privatednszones'
| where properties.numberOfVirtualNetworkLinks == 0
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/privateendpoints'
            query     = @"
resources
| where type =~ 'microsoft.network/privateendpoints'
| extend connection = iff(array_length(properties.manualPrivateLinkServiceConnections) > 0, properties.manualPrivateLinkServiceConnections[0], properties.privateLinkServiceConnections[0])
| extend stateEnum = tostring(connection.properties.privateLinkServiceConnectionState.status)
| where stateEnum =~ 'Disconnected'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/virtualnetworkgateways'
            query     = @"
resources
| where type =~ 'microsoft.network/virtualnetworkgateways'
| extend vpnClientConfiguration = properties.vpnClientConfiguration
| extend Resource = id
| join kind=leftouter (
    resources
    | where type =~ 'microsoft.network/connections'
    | mv-expand Resource = pack_array(properties.virtualNetworkGateway1.id, properties.virtualNetworkGateway2.id) to typeof(string)
    | project Resource, connectionId = id, ConnectionProperties=properties
    ) on Resource
| where isempty(vpnClientConfiguration) and isempty(connectionId)
| project type, subscriptionId, Resource, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/ddosprotectionplans'
            query     = @"
resources
| where type =~ 'microsoft.network/ddosprotectionplans'
| where isnull(properties.virtualNetworks)
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.Web/connections'
            query     = @"
resources
| where type =~ 'Microsoft.Web/connections'
| project type, resourceId = id , apiName = name, subscriptionId, resourceGroup, tags, location
| join kind = leftouter (
    resources
    | where type =~ 'microsoft.logic/workflows'
    | extend resourceGroup, location, subscriptionId, properties
    | extend var_json = properties['parameters']['`$connections']['value']
    | mvexpand var_connection = var_json
    | where notnull(var_connection)
    | extend connectionId = extract('connectionId\\\":\\\"(.*?)\\\"', 1, tostring(var_connection))
    | project connectionId, name
    )
    on `$left.resourceId == `$right.connectionId
| where connectionId == ''
| project type, subscriptionId, Resource=resourceId, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.Web/certificates'
            query     = @"
resources
| where type =~ 'microsoft.web/certificates'
| extend expiresOn = todatetime(properties.expirationDate)
| where expiresOn <= now()
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })
    #endregion queries

    $queries = $queries.where({ $_.intent -eq 'cost savings' })
    Write-Host "$($queries.Count) 'cost savings' related ARG queries"

    $batchSize = [math]::ceiling($queries.Count / $azAPICallConf['htParameters'].ThrottleLimit)
    $counterBatch = [PSCustomObject] @{ Value = 0 }
    $queriesBatch = ($queries) | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
    Write-Host " Processing queries in $($queriesBatch.Count) batches"

    $queriesBatch | ForEach-Object -Parallel {
        $arrayOrphanedResources = $using:arrayOrphanedResources
        $subsToProcessInCustomDataCollection = $using:subsToProcessInCustomDataCollection
        $azAPICallConf = $using:azAPICallConf
        foreach ($queryDetail in $_.Group) {
            #Batching: https://learn.microsoft.com/azure/governance/resource-graph/troubleshoot/general#toomanysubscription
            $counterBatch = [PSCustomObject] @{ Value = 0 }
            $batchSize = 1000
            $subscriptionsBatch = $subsToProcessInCustomDataCollection | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }

            $currentTask = "Getting orphaned $($queryDetail.queryName)"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
            $method = 'POST'
            foreach ($batch in $subscriptionsBatch) {
                Write-Host " Getting orphaned $($queryDetail.queryName) for $($batch.Group.subscriptionId.Count) Subscriptions"
                $subscriptions = $batch.Group.subscriptionId

                $bodyObject = @{
                    query         = $queryDetail.query
                    subscriptions = $subscriptions
                    options       = @{
                        '$top' = 1000
                    }
                }
                $bodyJson = $bodyObject | ConvertTo-Json

                $azapiCallParametersSplat = @{
                    AzAPICallConfiguration = $azAPICallConf
                    uri                    = $uri
                    method                 = $method
                    body                   = $bodyJson
                    listenOn               = 'Content'
                    currentTask            = $currentTask
                }
                $res = AzAPICall @azapiCallParametersSplat

                if ($res.count -gt 0) {
                    foreach ($resource in $res) {
                        $null = $script:arrayOrphanedResources.Add($resource)
                    }
                }
                Write-Host "  $($res.count) orphaned $($queryDetail.queryName) found"
            }
        }
    } -ThrottleLimit $azAPICallConf['htParameters'].ThrottleLimit

    if ($arrayOrphanedResources.Count -gt 0) {

        Write-Host " Found $($arrayOrphanedResources.Count) orphaned/unused Resources"
        Write-Host " Exporting OrphanedResources CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_orphanedResources.csv'"
        $arrayOrphanedResources | Sort-Object -Property Resource | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_orphanedResources.csv" -Delimiter "$csvDelimiter" -NoTypeInformation

    }
    else {
        Write-Host ' No orphaned/unused Resources found'
    }

    $end = Get-Date
    Write-Host "Getting orphaned/unused resources (ARG) processing duration: $((New-TimeSpan -Start $start -End $end).TotalMinutes) minutes ($((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds)"
}
#endregion functions

setOutput

#region verifyModules3rd
$modules = [System.Collections.ArrayList]@()
$null = $modules.Add([PSCustomObject]@{
        ModuleName         = 'AzAPICall'
        ModuleVersion      = $AzAPICallVersion
        ModuleProductName  = 'AzAPICall'
        ModulePathPipeline = 'AzAPICallModule'
    })
verifyModules3rd -modules $modules
#endregion verifyModules3rd

#region initAZAPICall
Write-Host "Initialize 'AzAPICall'"
$parameters4AzAPICallModule = @{
    DebugAzAPICall           = $DebugAzAPICall
    SubscriptionId4AzContext = $SubscriptionId4AzContext
}
$azAPICallConf = initAzAPICall @parameters4AzAPICallModule
Write-Host " Initialize 'AzAPICall' succeeded" -ForegroundColor Green
addHtParameters
#endregion initAZAPICall

#region get subscription details ARG
$currentTask = "get Subscription details for $($SubscriptionIds) subscriptions"
$uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
$method = 'POST'
$query = @"
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions' and properties.state =~ 'Enabled' and properties.subscriptionPolicies.quotaId in ('EnterpriseAgreement_2014-09-01','MSDNDevTest_2014-09-01','MSDN_2014-09-01','PayAsYouGo_2014-09-01') and subscriptionId in ($("'{0}'" -f ($SubscriptionIds -join "','")))
"@

$bodyObject = @{
    query = $query
}
$bodyJson = $bodyObject | ConvertTo-Json

$azapiCallParametersSplat = @{
    uri                    = $uri
    method                 = $method
    body                   = $bodyJson
    AzAPICallConfiguration = $azAPICallConf
    listenOn               = 'Content'
    currentTask            = $currentTask
}
$subscriptionsDetailed = AzAPICall @azapiCallParametersSplat

if ($subscriptionsDetailed.Count -ne $SubscriptionIds.Count) {
    Write-Host "Only '$($subscriptionsDetailed.Count)' of expected '$($SubscriptionIds.Count)' subscriptions from `$SubscriptionIds were returned from ARG"
    $compareReturnedVsExpected = Compare-Object -ReferenceObject $SubscriptionIds -DifferenceObject ($subscriptionsDetailed.subscriptionId)
    Write-Host " Missing Subscriptions: $($compareReturnedVsExpected.InputObject -join ', ')"
    throw
}
else {
    Write-Host "'$($subscriptionsDetailed.Count)' subscriptions were returned from ARG"
}

$htSubscriptionsLookup = @{}
foreach ($subscription in $subscriptionsDetailed) {
    $htSubscriptionsLookup.($subscription.subscriptionId) = $subscription
}
#endregion get subscription details ARG

$getOrphanedResourcesParametersSplat = @{
    subsToProcessInCustomDataCollection = $subscriptionsDetailed
    arrayOrphanedResources              = $arrayOrphanedResources
}
getOrphanedResources @getOrphanedResourcesParametersSplat

if ($arrayOrphanedResources.Count -gt 0) {

    $allCostManagementData = [System.Collections.ArrayList]@()
    $orphanedResourcesGroupedBySubscription = $arrayOrphanedResources | Group-Object -Property subscriptionId

    Write-Host "$($arrayOrphanedResources.Count) orphaned resources in $(($orphanedResourcesGroupedBySubscription | Measure-Object).Count) subscription(s) detected"
    Write-Host "AzureConsumptionPeriod: $AzureConsumptionPeriod; AzureConsumptionStartDate: $azureConsumptionStartDate - AzureConsumptionEndDate: $azureConsumptionEndDate"
    Write-Host " Chosen culture for number formatting: '$NumberCulture'"
    $numberCultureObject = New-Object System.Globalization.CultureInfo($NumberCulture)
    foreach ($entry in $orphanedResourcesGroupedBySubscription) {
        $subscriptionId = $entry.Name
        $bodyObject = @{
            type       = 'ActualCost' #AmortizedCost, ActualCost
            dataset    = @{
                granularity = 'none'
                filter      = @{

                    dimensions = @{
                        name     = 'ResourceId'
                        operator = 'In'
                        values   = $(if ($entry.Group.Resource.Count -gt 1) { $entry.Group.Resource } else { , @($entry.Group.Resource) }) #,@($entry.Group.Resource) the leading comma is important so, that convertto-json actually created an array element even for only a single entry - else it would create a string, which would make the payload ivalid for the api to process
                    }

                }
                aggregation = @{
                    totalCost = @{
                        name     = 'PreTaxCost'
                        function = 'Sum'
                    }
                }
                grouping    = @(
                    @{
                        type = 'Dimension'
                        name = 'SubscriptionId'
                    }
                    @{
                        type = 'Dimension'
                        name = 'ResourceType'
                    }
                    @{
                        type = 'Dimension'
                        name = 'ResourceId'
                    }
                    @{
                        type = 'Dimension'
                        name = 'ResourceGroupName'
                    }
                )
            }
            timeframe  = 'Custom'
            timeperiod = @{
                from = "$azureConsumptionStartDate"
                to   = "$azureConsumptionEndDate"
            }
        }
        $bodyJson = ConvertTo-Json -Depth 99 $bodyObject

        $currentTask = "get cost for SubscriptionId '$subscriptionId' for $($entry.Group.Count) orphaned Resources"
        Write-Host $currentTask
        $uriCostManagement = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($subscriptionId)/providers/Microsoft.CostManagement/query?api-version=2024-01-01&`$top=5000"
        $method = 'POST'
        $costManagementDataFromAPI = $null
        #use AzAPICall
        $costManagementDataFromAPIParametersSplat = @{
            AzAPICallConfiguration = $azAPICallConf
            uri                    = $uriCostManagement
            method                 = $method
            body                   = $bodyJson
            currentTask            = $currentTask
            listenOn               = 'ContentProperties'
        }
        $costManagementDataFromAPI = AzAPICall @costManagementDataFromAPIParametersSplat
        Write-Host " $currentTask returned $($costManagementDataFromAPI.properties.rows.Count) cost entries"

        foreach ($consumptionline in $costManagementDataFromAPI.properties.rows) {
            $hlper = $htSubscriptionsLookup.($consumptionline[1])

            $columnNames = $costManagementDataFromAPI.properties.columns.name
            $null = $allCostManagementData.Add([PSCustomObject]@{

                    "$($columnNames[1])"                   = $consumptionline[1]
                    SubscriptionName                       = $hlper.name
                    Responsible                            = $hlper.tags.Responsible
                    SecondaryContact                       = $hlper.tags.SecondaryContact
                    TechnicalContact                       = $hlper.tags.TechnicalContact
                    OrganizationalDivision                 = $hlper.tags.OrganizationalDivision
                    quotaId                                = $hlper.properties.subscriptionPolicies.quotaId
                    ManagementGroup                        = $hlper.properties.managementGroupAncestorsChain[0].name
                    #SubscriptionMgPath  = $hlper.ParentNameChainDelimited
                    "$($columnNames[2])"                   = $consumptionline[2]
                    "$($columnNames[3])"                   = $consumptionline[3]
                    resourceName                           = ($consumptionline[3] -replace '.*/')
                    "$($columnNames[4])"                   = $consumptionline[4]
                    "$($columnNames[0])_asIs"              = $consumptionline[0]
                    # PreTaxCostDe           = $([cultureinfo]::currentculture = 'de-DE'; '{0}' -f [decimal]$consumptionline[0])
                    "$($columnNames[0])_$($NumberCulture)" = $consumptionline[0].ToString($numberCultureObject)
                    "$($columnNames[5])"                   = $consumptionline[5]
                    # "$($columnNames[5])"  = $consumptionline[5]
                    # "$($columnNames[6])"  = $consumptionline[6]
                    # "$($columnNames[7])"  = $consumptionline[7]
                    # "$($columnNames[8])"  = $consumptionline[8]
                    # "$($columnNames[9])"  = $consumptionline[9]
                    # "$($columnNames[10])" = $consumptionline[10]
                    # "$($columnNames[11])" = $consumptionline[11]
                    # "$($columnNames[12])" = $consumptionline[12]
                    # "$($columnNames[13])" = $consumptionline[13]
                    # "$($columnNames[14])" = $consumptionline[14]
                    # "$($columnNames[15])" = $consumptionline[15]
                })
        }
    }

    Write-Host "Summary: Found $($allCostManagementData.Count) orphaned/unused Resources cost entries"
    $allCostManagementData | Group-Object -Property ResourceType | Sort-Object -Property Count -Descending | ForEach-Object {
        Write-Host " $($_.Count) orphaned/unused Resources of type '$($_.Name)' totalCost: $(($_.Group.PreTaxCost_asIs | Measure-Object -Sum).Sum)"
    }
    Write-Host "Exporting OrphanedResources with cost CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_orphanedResourcesCost.csv'"
    $allCostManagementData | Sort-Object -Property ResourceId | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_orphanedResourcesCost.csv" -Delimiter "$csvDelimiter" -NoTypeInformation

}
else {
    Write-Host 'No orphaned resources detected'
}

