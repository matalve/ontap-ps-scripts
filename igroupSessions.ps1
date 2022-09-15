<#
.SYNOPSIS
    Count iSCSI sessions/FC logins per igroup in NetApp cluster.

.DESCRIPTION
    Count iSCSI sessions/FC logins per igroup in NetApp cluster.

.PARAMETER <-Cluster>
    Name of the Netapp Cluster.

.PARAMETER <-Vserver>
    (Optional) Name of the Netapp Vserver.

.PARAMETER <-Protocol>
    (Optional) Either iSCSI or FCP.

.EXAMPLE
    .\igroupSessions.ps1 -Cluster Cluster1
    Listing count per igroup on Cluster Cluster1 for all vservers and SAN protocols.

.EXAMPLE
    .\igroupSessions.ps1 -Cluster Cluster1 -Vserver vserver1
    Listing count per igroup on Cluster Cluster1 for the vserver1 vserver and all SAN protocols.

.EXAMPLE
    .\igroupSessions.ps1 -Cluster Cluster1 -Vserver vserver1 -Protocol iscsi
    Listing count per igroup on Cluster Cluster1 for the vserver1 vserver and only the iSCSI protocol.
#>


param(
[Parameter(Mandatory=$true)][string]$Cluster,
[Parameter(Mandatory=$false)][string]$Vserver,
[Parameter(Mandatory=$false)][ValidateSet('iscsi','fcp')][string]$Protocol
)

# Triggering credential pop-out
$Credentials = Get-Credential -Credential "DOMAIN\"
#Write-Host $Credentials.GetNetworkCredential().username $Credentials.GetNetworkCredential().password -ForegroundColor Gray

if ($Credentials.GetNetworkCredential().Domain) {
    $user = $Credentials.GetNetworkCredential().Domain + "\" + $Credentials.GetNetworkCredential().username
} else {
    $user = $Credentials.GetNetworkCredential().username
}

$pass = $Credentials.GetNetworkCredential().password

# Call this function to send API request to $Cluster
function QueryAPI([string]$Cluster, [string]$Resource)
{
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $baseURL = "https://" + $Cluster
        $credPair = "$($user):$($pass)"
        $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
        $header = @{ Authorization = "Basic $encodedCredentials" }

    } catch {
        Write-Host "Issues with the SSL / TLS functions in the script" -ForegroundColor Red
        Write-Host $_ -ForegroundColor Red

        exit
    }
    
    # Building the URL to transmit
    $Query = $baseURL + $Resource

    try {
         $queryResponse = Invoke-RestMethod -Method GET -Uri $Query -Headers $header
    } catch {
         Write-Host "Failed to request information" -ForegroundColor Red
         Write-Host $Query -ForegroundColor Red
         Write-Host $_ -ForegroundColor Red
         exit
    }

    return $queryResponse
}

# Command "Invoke-RestMethod" requires language mode FullLanguage - uncomment block if check is needed
<# if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
    Write-Host "Script is running in the wrong langugage mode (ConstrainedLanguage)" -ForegroundColor Red
    Write-Host "It needs to run in FullLanguage mode instead"

    exit
} #>

# Building the filter for the query, always excluding "other side" Metrocluster SVM since we can't get data there anyway
$filterString = "svm.name=!*-mc"

if ($Vserver -ne "") {
    $filterString = $filterString + "," + $Vserver
    Write-Verbose $Vserver -ForegroundColor Gray
}

if ($Protocol -ne "") {
    $filterString = $filterString + "&igroup.protocol=" + $Protocol
    Write-Verbose $Protocol -ForegroundColor Gray
}

# GET LUN mappings for whatever was requested, including protocol, since it's only interesting to see sessions for igroups in use
$queryLunMappings = "/api/protocols/san/lun-maps?" + $filterString + "&fields=igroup.protocol&return_records=true&return_timeout=15"
#Write-Host "API request: `t" $queryLunMappings -ForegroundColor Gray
$response_queryLunMappings = QueryAPI $Cluster $queryLunMappings

Write-Verbose "Found $($response_queryLunMappings.num_records) LUN mappings"

# Array of igroups used to store the list of igroups, per protocol
$iscsi_igroupArray = New-Object System.Collections.ArrayList($null)
$fcp_igroupArray = New-Object System.Collections.ArrayList($null)

# Output arrays
$iscsiResultsArray = New-Object System.Collections.ArrayList($null)
$fcpResultsArray = New-Object System.Collections.ArrayList($null)

# Sort the LUN mappings into arrays based on protocol, using the UUID since multiple igroups can exist with the same name
foreach ($lunMapping in $response_queryLunMappings.records) {
    #Write-Host $lunMapping.igroup.name -ForegroundColor Gray

    if ($lunMapping.igroup.protocol -eq "iscsi"){
        [void]$iscsi_igroupArray.Add($lunMapping.igroup.uuid)

    } elseif ($lunMapping.igroup.protocol -eq "fcp") {
        [void]$fcp_igroupArray.Add($lunMapping.igroup.uuid)

    } else {
        # Fall-back since the script doesn't know what to do with protocol "mixed" or other unknowns
        Write-Host "Unknown protocol:" $lunMapping.igroup.name $lunMapping.igroup.protocol -ForegroundColor Gray
    }
}

# Removing duplicates of igroups to get a shorter list - Sort is required for Get-Unique
$iscsi_igroupArrayUnique = $iscsi_igroupArray | Sort-Object | Get-Unique
$fcp_igroupArrayUnique = $fcp_igroupArray | Sort-Object | Get-Unique

# Functions need to be defined before they are called - scroll past them to see how they are called

function iscsiSessions(){

    # Used for the progress bar
    [int] $i = 1

    # Getting the session count per igroup and putting it in an array for output
    foreach ($igroupUUID in $iscsi_igroupArrayUnique) {

        # GET sessions for the igroup but don't return the data, only the amount of sessions are interesting
        $querySessions = "/api/protocols/san/iscsi/sessions?igroups.uuid=" + $igroupUUID + "&return_records=false&return_timeout=15"
        #Write-Host "API request: `t" $querySessions -ForegroundColor Gray
        $response_querySessions = QueryAPI $Cluster $querySessions

        # GET igroup name since that reference was lost when the array of UUID was made
        $queryIgroup = "/api/protocols/san/igroups/" + $igroupUUID + "?fields=svm"
        $response_queryIgroup = QueryAPI $Cluster $queryIgroup

        # Progress bar
        Write-Progress "Counting sessions for $($response_queryIgroup.name)" -PercentComplete (($i / $iscsi_igroupArrayUnique.length) *100)

        # Declaring and resetting the string used for easy overview of which igroups stands out in the amount of sessions
        [String] $visualAid = ""

        # Add the same number of symbols to the string as there are sessions
        if ($response_querySessions.num_records -gt 0) {
            For ($k = $response_querySessions.num_records; $k -gt 0; $k --){
                $visualAid += "*"
            }
        }

        # Creating a custom object for output in a nice table
        $newRecord = New-Object PSObject -property @{
            Vserver = $response_queryIgroup.svm.name
            Igroup = $response_queryIgroup.name
            Sessions = $response_querySessions.num_records
            Visual = [String]$visualAid
        }

        # Adding the object to the output array
        [void]$iscsiResultsArray.Add($newRecord)

        # Increasing the progress
        $i++
    }

    # Outputting results array
    $iscsiResultsArray | Sort-Object -Property Vserver | Format-Table Vserver,Igroup,Sessions,Visual
}

function fcpLogins(){

    # Used for the progress bar
    [int]$i = 1

    # Getting the login count per igroup and putting it in an array for output
    foreach ($igroupUUID in $fcp_igroupArrayUnique) {

        # GET logins for the igroup but don't return the data, only the amount of sessions are interesting
        $queryLogins = "/api/network/fc/logins?igroups.uuid=" + $igroupUUID + "&return_records=false&return_timeout=15"
        #Write-Host "API request: `t" $queryLogins -ForegroundColor Gray
        $response_queryLogins = QueryAPI $Cluster $queryLogins

        # GET igroup name since that reference was lost when the array of UUID was made
        $queryIgroup = "/api/protocols/san/igroups/" + $igroupUUID + "?fields=svm"
        $response_queryIgroup = QueryAPI $Cluster $queryIgroup
        
        # Progress bar
        Write-Progress "Counting logins for $($response_queryIgroup.name)" -PercentComplete (($i / $fcp_igroupArrayUnique.length) *100)

        # Declaring and resetting the string used for easy overview of which igroups stands out in the amount of sessions
        [String] $visualAid = ""

        # Add the same number of symbols to the string as there are sessions
        if ($response_queryLogins.num_records -gt 0) {
            for ($k = $response_queryLogins.num_records; $k -gt 0; $k --){
                $visualAid += "*"
            }
        }

        # Creating a custom object for output in a nice table
        $newRecord = New-Object PSObject -property @{
            Vserver = $response_queryIgroup.svm.name
            Igroup = $response_queryIgroup.name
            Logins = $response_queryLogins.num_records
            Visual = [String]$visualAid
        }

        # Adding the object to the output array
        [void]$fcpResultsArray.Add($newRecord)

        # Increasing the progress
        $i++
    }

    # Outputting results array
    $fcpResultsArray | Sort-Object -Property Vserver | Format-Table Vserver,Igroup,Logins,Visual
}

if ($Protocol -eq "iscsi"){
    iscsiSessions
    
} elseif ($Protocol -eq "fcp"){
    fcpLogins

} else {
    # When no protocol is specified as a parameter - output both
    Write-Output "iSCSI igroups:"
    iscsiSessions

    Write-Output "`nFCP igroups:"
    fcpLogins
}
