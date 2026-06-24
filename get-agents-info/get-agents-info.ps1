# PowerShell version of get-agents-info.py

function Read-CredsFile {
    param(
        [string]$FileName = "../.creds"
    )
    
    $creds = @{}
    
    if (Test-Path $FileName) {
        Get-Content $FileName | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith("#")) {
                $parts = $line.Split("=", 2)
                if ($parts.Count -eq 2) {
                    $creds[$parts[0]] = $parts[1]
                }
            }
        }
    } else {
        Write-Host "Warning: $FileName file not found. Please input values."
    }
    
    return $creds
}

function Get-AgentVersions {
    param(
        [hashtable]$Headers,
        [hashtable]$Params,
        [string]$OrgId,
        [string]$ContrastUrl
    )
    
    $tempHeaders = $Headers.Clone()
    $authToken = $tempHeaders["Authorization"]
    $tempHeaders["Authorization"] = "Basic $authToken"
    
    $url = "$ContrastUrl/api/ng/$OrgId/agents/versions"
    
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $tempHeaders -Method Get
        return @{
            StatusCode = 200
            Data = $response
        }
    } catch {
        return @{
            StatusCode = $_.Exception.Response.StatusCode.value__
            Data = $null
        }
    }
}

function Get-Agents {
    param(
        [hashtable]$Headers,
        [string]$OrgId,
        [string]$ContrastUrl
    )
    
    # Remove /Contrast suffix if present in the base URL for v4 API
    $baseUrl = $ContrastUrl.TrimEnd('/') -replace '/Contrast$', ''
    $url = "$baseUrl/api/v4/organizations/$OrgId/agents?sort=lastActive,desc&page=0&size=10"
    
    try {
        $webRequest = [System.Net.HttpWebRequest]::Create($url)
        $webRequest.Method = "GET"
        $webRequest.Headers.Add("Accept", $Headers["Accept"])
        $webRequest.Headers.Add("Authorization", $Headers["Authorization"])
        $webRequest.Headers.Add("API-Key", $Headers["API-Key"])
        
        $webResponse = $webRequest.GetResponse()
        $responseStream = $webResponse.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseStream)
        $responseText = $reader.ReadToEnd()
        $reader.Close()
        $webResponse.Close()
        
        $response = $responseText | ConvertFrom-Json
        
        return @{
            StatusCode = 200
            Data = $response
        }
    } catch {
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 500 }
        return @{
            StatusCode = $statusCode
            Data = $null
        }
    }
}

function Get-AgentConfig {
    param(
        [hashtable]$Headers,
        [string]$OrgId,
        [string]$AgentId,
        [string]$AppId,
        [string]$ContrastUrl
    )
    
    # Remove /Contrast suffix if present in the base URL for v4 API
    $baseUrl = $ContrastUrl.TrimEnd('/') -replace '/Contrast$', ''
    $url = "$baseUrl/api/v4/organizations/$OrgId/agents/$AgentId/applications/$AppId/effective-config"
    
    try {
        $webRequest = [System.Net.HttpWebRequest]::Create($url)
        $webRequest.Method = "GET"
        $webRequest.Headers.Add("Accept", $Headers["Accept"])
        $webRequest.Headers.Add("Authorization", $Headers["Authorization"])
        $webRequest.Headers.Add("API-Key", $Headers["API-Key"])
        
        $webResponse = $webRequest.GetResponse()
        $responseStream = $webResponse.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseStream)
        $responseText = $reader.ReadToEnd()
        $reader.Close()
        $webResponse.Close()
        
        $response = $responseText | ConvertFrom-Json
        
        return @{
            StatusCode = 200
            Data = $response
        }
    } catch {
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 500 }
        return @{
            StatusCode = $statusCode
            Data = $null
        }
    }
}

function Show-ConfigData {
    param(
        [object]$ConfigData,
        [int]$Indent = 4
    )
    
    $indentStr = " " * $Indent
    
    if ($ConfigData -is [hashtable] -or $ConfigData -is [PSCustomObject]) {
        $props = if ($ConfigData -is [hashtable]) { $ConfigData.Keys } else { $ConfigData.PSObject.Properties.Name }
        
        foreach ($key in $props) {
            $value = if ($ConfigData -is [hashtable]) { $ConfigData[$key] } else { $ConfigData.$key }
            
            if ($value -is [hashtable] -or $value -is [PSCustomObject]) {
                Write-Host "${indentStr}${key}:"
                Show-ConfigData -ConfigData $value -Indent ($Indent + 2)
            } elseif ($value -is [array]) {
                Write-Host "${indentStr}${key}: $($value | ConvertTo-Json -Compress -Depth 1)"
            } else {
                Write-Host "${indentStr}${key}: $value"
            }
        }
    }
}

# Main script
$creds = Read-CredsFile

$contrastUrl = $creds["CONTRAST_URL"]
$orgId = $creds["ORG_ID"]
$username = $creds["USERNAME"]
$apiKey = $creds["API_KEY"]
$serviceKey = $creds["SERVICE_KEY"]

# Prompt for values
$urlInput = Read-Host "Enter your Contrast URL (blank will use default '$contrastUrl')"
if ($urlInput.Trim()) {
    $contrastUrl = $urlInput
} elseif (-not $contrastUrl) {
    while (-not $contrastUrl) {
        Write-Host "Contrast URL cannot be blank."
        $contrastUrl = Read-Host "Enter your Contrast URL"
    }
}

$orgInput = Read-Host "Enter your Organization ID (blank will use default '$orgId')"
if ($orgInput.Trim()) {
    $orgId = $orgInput
} elseif (-not $orgId) {
    while (-not $orgId) {
        Write-Host "Organization ID cannot be blank."
        $orgId = Read-Host "Enter your Organization ID"
    }
}

$userInput = Read-Host "Enter your username (blank will use default '$username')"
if ($userInput.Trim()) {
    $username = $userInput
} elseif (-not $username) {
    while (-not $username) {
        Write-Host "Username cannot be blank."
        $username = Read-Host "Enter your username"
    }
}

$apiKeyInput = Read-Host "Enter your API key (blank will use default '****************************')"
if ($apiKeyInput.Trim()) {
    $apiKey = $apiKeyInput
} elseif (-not $apiKey) {
    while (-not $apiKey) {
        Write-Host "API key cannot be blank."
        $apiKey = Read-Host "Enter your API key"
    }
}

$serviceKeyInput = Read-Host "Enter your service key (blank will use default '************')"
if ($serviceKeyInput.Trim()) {
    $serviceKey = $serviceKeyInput
} elseif (-not $serviceKey) {
    while (-not $serviceKey) {
        Write-Host "Service key cannot be blank."
        $serviceKey = Read-Host "Enter your service key"
    }
}

# Create authorization header
$authString = "${username}:${serviceKey}"
$authBytes = [System.Text.Encoding]::UTF8.GetBytes($authString)
$authB64 = [Convert]::ToBase64String($authBytes)

$headers = @{
    "Accept" = "application/json"
    "Authorization" = $authB64
    "API-Key" = $apiKey
}

$params = @{
    "expand" = @("apps", "vulns")
}

# Get agent versions
Write-Host ""
$versionResponse = Get-AgentVersions -Headers $headers -Params $params -OrgId $orgId -ContrastUrl $contrastUrl
Write-Host "Agent Versions response status code: $($versionResponse.StatusCode)"
if ($versionResponse.StatusCode -eq 200) {
    Write-Host ($versionResponse.Data | ConvertTo-Json -Depth 10)
}

# Get agents
$agentResponse = Get-Agents -Headers $headers -OrgId $orgId -ContrastUrl $contrastUrl
Write-Host "Agents response status code: $($agentResponse.StatusCode)"

if ($agentResponse.StatusCode -eq 200) {
    $data = $agentResponse.Data
    
    # Save to JSON file
    $data | ConvertTo-Json -Depth 100 | Out-File "output.json"
    Write-Host "Applications response saved to output.json"
    
    if ($data.content) {
        $agents = $data.content
        Write-Host "`nFound $($agents.Count) agents:`n"
        
        foreach ($agent in $agents) {
            $fullAgentId = $agent.id
            
            # Split the agent ID - format is "app_id:agent_id"
            if ($fullAgentId -match ':') {
                $idParts = $fullAgentId.Split(':', 2)
                $appId = $idParts[0]
                $agentId = $idParts[1]
            } else {
                Write-Host "Warning: Could not parse agent ID: $fullAgentId"
                continue
            }
            
            Write-Host "Agent ID: $fullAgentId"
            Write-Host "  App ID: $appId"
            Write-Host "  Agent Instance ID: $agentId"
            Write-Host "  Application: $($agent.applicationName)"
            Write-Host "  Server: $($agent.serverName)"
            Write-Host "  Language: $($agent.language)"
            Write-Host "  Version: $($agent.displayVersion)"
            Write-Host "  Status: $($agent.status)"
            Write-Host "  Environment: $($agent.environment)"
            Write-Host "  Last Active: $($agent.lastActive)"
            Write-Host "  Hostname: $($agent.hostname)"
            
            # Add server inventory details if available
            if ($agent.serverInventory) {
                $inventory = $agent.serverInventory
                Write-Host "  OS: $($inventory.operatingSystem)"
                Write-Host "  Runtime: $($inventory.runtimeVersion)"
                Write-Host "  Docker: $($inventory.isDocker), Kubernetes: $($inventory.isKubernetes)"
            }
            
            # Get agent configuration
            $configResponse = Get-AgentConfig -Headers $headers -OrgId $orgId -AgentId $agentId -AppId $appId -ContrastUrl $contrastUrl
            if ($configResponse.StatusCode -eq 200) {
                Write-Host "  Config retrieved successfully"
                Write-Host "  Effective Config:"
                
                $configData = $configResponse.Data
                Show-ConfigData -ConfigData $configData -Indent 4
            } else {
                Write-Host "  Config retrieval failed: $($configResponse.StatusCode)"
            }
            
            Write-Host ""  # Blank line between agents
        }
    } else {
        Write-Host "No agents found in response."
    }
}
