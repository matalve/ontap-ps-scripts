<#
.SYNOPSIS
    Enabling encryption of unencrypted volumes

.DESCRIPTION
    Since Best practise says maximum four concurrent volume encryption conversions per node;
    this script honors that and starts the conversion.

    Source:
    https://kb.netapp.com/Advice_and_Troubleshooting/Data_Storage_Software/ONTAP_OS/FAQ%3A_NetApp_Volume_Encryption_and_NetApp_Aggregate_Encryption
    - Is there a maximum number of simultaneous volume encryption conversion processes that can be run at one time?
    No, but it is it is recommended to have no more than 4 combined encryption conversions or encryption volume moves per node at the same time.

.PARAMETER <-Clusters>
    Name of the Netapp Clusters to start converting volumes on.

.EXAMPLE
    .\volEncConversion.ps1 -Cluster Cluster1,Cluster2
    Starting volumes encryption conversions on clusters Cluster1 and Cluster2.
#>

param(
    [Parameter(Mandatory = $true)][array]$Clusters
)

# Command "Invoke-RestMethod" requires language mode FullLanguage - uncomment block if check is needed
<# if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
    Write-Host "Script is running in the wrong langugage mode (ConstrainedLanguage)" -ForegroundColor Red
    Write-Host "It needs to run in FullLanguage mode instead"
    exit
} #>

# Replace DOMAIN with your domain
$Credentials = Get-Credential -Credential "DOMAIN\"

if ($Credentials.GetNetworkCredential().Domain) {
        $user = $Credentials.GetNetworkCredential().Domain + "\" + $Credentials.GetNetworkCredential().UserName
}
else {
        $user = $Credentials.GetNetworkCredential().UserName
}
    
$pass = $Credentials.GetNetworkCredential().Password

function QueryAPI([string]$Method, [string]$Cluster, [string]$Resource, [string]$Body) {    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $baseURL = "https://" + $Cluster
        #$decodedPass = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($pass))
        #$credPair = "$($user):$($decodedPass)"
        $credPair = "$($user):$($pass)"
        $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
        $header = @{ Authorization = "Basic $encodedCredentials" }

    }
    catch {
        Write-Host "Issues with the SSL / TLS functions in the script" -ForegroundColor Red
        Write-Host $_ -ForegroundColor Red
        exit
    }
    
    # Building the URL to transmit
    $Query = $baseURL + $Resource

    try {
        if ($Method -eq "PATCH") {
            #Write-Host "Invoke-Rest with body" -ForegroundColor Gray
            $queryResponse = Invoke-RestMethod -Method $Method -Uri $Query -Headers $header -Body $Body
        }
        else {
            #Write-Host "Invoke-Rest without body" -ForegroundColor Gray
            $queryResponse = Invoke-RestMethod -Method $Method -Uri $Query -Headers $header
        }
    }
    catch {
        Write-Host "Failed to request information" -ForegroundColor Red
        Write-Host $Query -ForegroundColor Red
        Write-Host $_ -ForegroundColor Red
        exit
    }

    return $queryResponse
}

<#
Runbook per Cluster:
* Check for key-manager
* Check ongoing volume encryption conversions
* Get list of nodes
* Count how many ongoing conversions per node
* Get (4 minus ongoing) volumes per node
* Start conversions for the volumes
#>

foreach ($Cluster in $Clusters) {

    # Checking if key-manager is configured, can't encrypt volumes if it is not configured.
    $queryKeyManager = "/api/security/key-managers?return_timeout=15&return_records=true"
    $response_queryKeyManager = QueryAPI -Method "GET" -Cluster $Cluster -Resource $queryKeyManager

    if ($response_queryKeyManager.num_records -eq 0) {
        Write-Host "Cluster $($Cluster) does not have a key-manager configured - skipping" -ForegroundColor Yellow
    }
    else {
        #Write-Verbose "--- Getting list of ongoing encryption conversions on $($Cluster)"
        Write-Host "Checking ongoing volume encryption conversions on cluster $($Cluster)" -ForegroundColor Cyan
        $queryOngoingConversions = "/api/private/cli/volume/encryption/conversion"
        $response_queryOngoingConversions = QueryAPI -Method "GET" -Cluster $Cluster -Resource $queryOngoingConversions

        Write-Verbose "--- Getting list of aggregates available on $($Cluster)"
        $queryAggregates = "/api/storage/aggregates?return_records=true&return_timeout=15"
        $response_queryAggregates = QueryAPI -Method "GET" -Cluster $Cluster -Resource $queryAggregates

        #Write-Output "--- Aggregates on $($Cluster):"
        #Write-Output $response_queryAggregates.records
        #Write-Output "---"

        # Hash table for translating which aggregate belong to which node
        $nodeAggr = @{}

        Write-Verbose "--- Creating translation table for aggregate owner"
        foreach ($aggregate in $response_queryAggregates.records) {
            #Write-Verbose "$($aggregate.node.name) $($aggregate.name)"
            $nodeAggr.Add($aggregate.name, $aggregate.node.name)
        }
        #$nodeAggr

        # Hash table for keeping track of how many times an aggregate shows up in the ongoing conversions
        $nodeCount = @{}
    
        foreach ($volume in $response_queryOngoingConversions.records) {

            Write-Verbose "--- Getting aggregate for: $($volume.vserver) $($volume.volume) on $($Cluster)"
            $queryOngoingVolume = "/api/storage/volumes?name=" + $volume.volume + "&svm.name=" + $volume.vserver + "&fields=aggregates.name&return_records=true&return_timeout=15"
            $response_queryOngoingVolume = QueryAPI -Method "GET" -Cluster $Cluster -Resource $queryOngoingVolume

            $volNode = $nodeAggr[$response_queryOngoingVolume.records.aggregates.name]
            Write-Verbose "--- Volume and node: $($volume.volume) $($volNode)"

            # Adding count to Node hashtable, to keep track of how many active conversions per node
            if ($nodeCount[$volNode]) {
                [int]$value = $nodeCount[$volNode] + 1
                $nodeCount[$volNode] = $value
            }
            # If Node is not already in the hashtable, then it's set to a count of one (first entry)
            else {
                [int]$value = 1
                $nodeCount.Add($volNode, $value)
            }            
        }

        #Write-Output "--- nodeCount"
        #$nodeCount

        $queryNodes = "/api/cluster/nodes?return_records=true&return_timeout=15"
        $response_queryNodes = QueryAPI -Method "GET" -Cluster $Cluster -Resource $queryNodes

        # Adding nodes without conversions to the hashtable
        foreach ($node in $response_queryNodes.records) {
            if (!$nodeCount[$node.name]) {
                $nodeCount.Add($node.name,0)
            }
        }
        #Write-Output "--- nodeCount after additions"
        #$nodeCount

        foreach ($node in $response_queryNodes.records) {
            Write-Verbose "--- Checking if count for node $($node.name) is less than 4"

            if ($nodeCount[$node.name] -lt 4) {
                Write-Verbose "--- nodeCount $($node.name) is less than 4"

                [int]$volCount = 4 - $nodeCount[$node.name]
                Write-Verbose "--- Looking for $($volCount) volumes to convert"

                Write-Verbose "--- Creating string of aggregates to search for volumes to convert"
                $queryAggregatesOnNode = "/api/storage/aggregates?node.name=" + $node.name + "&return_records=true&return_timeout=15"
                $response_queryAggregatesOnNode = QueryAPI -Method "GET" -Cluster $Cluster -Resource $queryAggregatesOnNode

                if ($response_queryAggregatesOnNode.num_records -gt 0) {
                    [string]$aggregateList = ""
                    foreach ($aggregate in $response_queryAggregatesOnNode.records) {
                        $aggregateList = $aggregateList + $aggregate.name + "|"
                    }
    
                    #Write-Verbose "--- aggregateList: $($aggregateList)"
    
                    # Removing last character ("|")
                    $aggregateList = $aggregateList.Substring(0,$aggregateList.Length-1)
                    Write-Verbose "--- aggregate list for node $($node.name): $($aggregateList)"
    
                    # Excluding the SVM root volumes since those has to be converted via "vol move"
                    # as well as any volumes with a comment containing "not encrypt", not on SVM "*-mc" and is not a constituent
                    $queryUnencryptedVolumes = "/api/storage/volumes?encryption.state=unencrypted&state=online&comment=!*not%20encrypt*&is_svm_root=false&is_constituent=false&svm.name=!*-mc&aggregates.name=" + $aggregateList + "&fields=svm.name,aggregates.name&max_records=" + $volCount + "&return_records=true&return_timeout=15"
                    $response_queryUnencryptedVolumes = QueryAPI -Method "GET" -Cluster $Cluster -Resource $queryUnencryptedVolumes
    
                    Write-Verbose "--- Found $($response_queryUnencryptedVolumes.num_records) volumes for conversion"
    
                    if ($response_queryUnencryptedVolumes.num_records -eq 0) {
                        Write-Host "Found no volumes to encrypt on node $($node.name)" -ForegroundColor Green
    
                    } else {
                        Write-Output "--- $($node.name) can start $($volCount) more conversions"
                        
                        if ($response_queryUnencryptedVolumes.num_records -lt $volCount) {
                            Write-Host "Found less volumes than requested: ($($response_queryUnencryptedVolumes.num_records) of $($volCount))" -ForegroundColor Yellow
                        }
    
                        foreach ($newVolume in $response_queryUnencryptedVolumes.records) {
                            #Write-Verbose "--- Requesting to start conversion of volume $($newVolume.name) $($newVolume.svm.name) $($newVolume.uuid) on aggregate $($aggregate.name)"
                            Write-Output "Starting conversion of volume $($newVolume.svm.name) $($newVolume.name) in $($newVolume.aggregates.name)"
        
                            # Support for "volume encryption conversion start" was added in Rest API 9.9, until then we have to use a workaround.
                            $queryStartConversion = "/api/storage/volumes/" + $newVolume.uuid + "?return_timeout=0&sizing_method=use_existing_resources"
        
                            $queryStartConversionBody = @{
                                "encryption" = @{"enabled" = "true" }
                            } | ConvertTo-Json
                            
                            # Sending output to unused variable so the job output is not sent to console.
                            #QueryAPI -Method "PATCH" -Cluster $Cluster -Resource $queryStartConversion -Body $queryStartConversionBody
                            $response_queryStartConversion = QueryAPI -Method "PATCH" -Cluster $Cluster -Resource $queryStartConversion -Body $queryStartConversionBody
                            Write-Verbose "--- Conversion requested"
                        }
                    }
                } else {
                    Write-Verbose "--- Node $($node.name) does not own any aggregate"
                }

            } else {
                Write-Host "$($node.name) already has 4 or more active conversions" -ForegroundColor Yellow
            }
        }
        # Divider to easier see when the script loops
        Write-Verbose "---"
    }
}
