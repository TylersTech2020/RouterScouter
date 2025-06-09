# Network Scan for Router Vulnerabilities with RouterSploit and Metasploit
# Requires: Run as Administrator, RouterSploit installed, Metasploit installed
# Usage: Modify $network, $range, $routerSploitPath, and $msfPath to match your setup

# Define network and paths
$network = "192.168.1" # Change to your network (e.g., "10.0.0" for 10.0.0.x)
$range = 1..254 # IP range to scan
$ports = 22, 23, 80, 443, 8080 # Common router ports: SSH, Telnet, HTTP, HTTPS, alt HTTP
$routerSploitPath = "C:\Path\To\routersploit" # Adjust to your RouterSploit directory
$msfPath = "C:\Path\To\metasploit-framework\bin\msfconsole.bat" # Adjust to your Metasploit msfconsole path
$outputFile = "RouterScanResults.txt"

"Network Scan Results - $(Get-Date)" | Out-File -FilePath $outputFile

# Function to test if host is alive (ping)
function Test-HostAlive {
    param ($ip)
    try {
        $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction Stop
        return $ping
    } catch {
        return $false
    }
}

# Function to scan ports with PowerShell (fallback)
function Scan-Ports {
    param ($ip, $ports)
    $openPorts = @()
    foreach ($port in $ports) {
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $tcp.Connect($ip, $port)
            if ($tcp.Connected) {
                $openPorts += $port
                $tcp.Close()
            }
        } catch {
            # Port closed or filtered
        }
    }
    return $openPorts
}

# Function for banner grabbing (basic HTTP/SSH check)
function Get-Banner {
    param ($ip, $port)
    try {
        if ($port -eq 80 -or $port -eq 8080 -or $port -eq 443) {
            $uri = if ($port -eq 443) { "https://$ip" } else { "http://$ip" }
            $response = Invoke-WebRequest -Uri $uri -TimeoutSec 5 -ErrorAction Stop
            $banner = $response.Headers["Server"]
            return "HTTP Banner: $banner"
        } elseif ($port -eq 22 -or $port -eq 23) {
            $tcp = New-Object Net.Sockets.TcpClient
            $tcp.Connect($ip, $port)
            $stream = $tcp.GetStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $banner = $reader.ReadLine()
            $tcp.Close()
            return "Service Banner (Port $port): $banner"
        }
    } catch {
        return "Banner Grab Failed (Port $port): $_"
    }
    return "No Banner (Port $port)"
}

# Function to test default credentials (basic HTTP example)
function Test-DefaultCredentials {
    param ($ip, $port)
    $credentials = @(
        @{ User = "admin"; Pass = "admin" },
        @{ User = "admin"; Pass = "password" },
        @{ User = "root"; Pass = "root" }
    )
    $uri = if ($port -eq 443) { "https://$ip" } else { "http://$ip" }
    foreach ($cred in $credentials) {
        try {
            $response = Invoke-WebRequest -Uri $uri -Credential (New-Object System.Management.Automation.PSCredential($cred.User, (ConvertTo-SecureString $cred.Pass -AsPlainText -Force))) -TimeoutSec 5 -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                return "VULNERABILITY: Default credentials worked! User: $($cred.User) Pass: $($cred.Pass)"
            }
        } catch {
            # Login failed, continue to next credential
        }
    }
    return "No default credentials found."
}

# Function to run RouterSploit scan
function Run-RouterSploitScan {
    param ($ip)
    if (-not (Test-Path $routerSploitPath)) {
        "ERROR: RouterSploit not found at $routerSploitPath. Install RouterSploit and update path." | Out-File -FilePath $outputFile -Append
        Write-Host "ERROR: RouterSploit not found at $routerSploitPath. Install RouterSploit and update path."
        return
    }
    try {
        # Change to RouterSploit directory
        Set-Location -Path $routerSploitPath
        $rsfScript = "python rsf.py"
        # Run autopwn scanner and basic credential check
        $command = "use scanners/autopwn; set target $ip; run; use creds/generic/http_default_creds; set target $ip; run; exit"
        $rsfOutput = $command | & $rsfScript
        "RouterSploit Scan for $ip :" | Out-File -FilePath $outputFile -Append
        $rsfOutput | Out-File -FilePath $outputFile -Append
    } catch {
        "ERROR: RouterSploit scan failed for $ip : $_" | Out-File -FilePath $outputFile -Append
        Write-Host "ERROR: RouterSploit scan failed for $ip : $_"
    } finally {
        # Return to original directory
        Set-Location -Path $PSScriptRoot
    }
}

# Function to run Metasploit scan
function Run-MetasploitScan {
    param ($ip)
    if (-not (Test-Path $msfPath)) {
        "ERROR: Metasploit not found at $msfPath. Install Metasploit and update path." | Out-File -FilePath $outputFile -Append
        Write-Host "ERROR: Metasploit not found at $msfPath. Install Metasploit and update path."
        return
    }
    try {
        # Create a temporary Metasploit resource script
        $msfScript = "msf_temp_$$.rc"
        $msfCommands = @"
use auxiliary/scanner/portscan/tcp
set RHOSTS $ip
set PORTS 22,23,80,443,8080
run
use auxiliary/scanner/http/http_version
set RHOSTS $ip
run
use auxiliary/scanner/http/http_login
set RHOSTS $ip
set USERPASS_FILE /path/to/wordlist.txt
set STOP_ON_SUCCESS true
run
exit
"@
        $msfCommands | Out-File -FilePath $msfScript -Encoding ASCII
        # Run Metasploit with the resource script
        $msfOutput = & $msfPath -q -r $msfScript
        "Metasploit Scan for $ip :" | Out-File -FilePath $outputFile -Append
        $msfOutput | Out-File -FilePath $outputFile -Append
        # Clean up temporary script
        Remove-Item -Path $msfScript -ErrorAction SilentlyContinue
    } catch {
        "ERROR: Metasploit scan failed for $ip : $_" | Out-File -FilePath $outputFile -Append
        Write-Host "ERROR: Metasploit scan failed for $ip : $_"
    }
}

# Main scan loop
Write-Host "Starting network scan for $network.x..."
foreach ($i in $range) {
    $ip = "$network.$i"
    Write-Host "Pinging $ip..."
    if (Test-HostAlive -ip $ip) {
        "Host $ip is alive" | Out-File -FilePath $outputFile -Append
        $openPorts = Scan-Ports -ip $ip -ports $ports
        if ($openPorts.Count -gt 0) {
            "Open ports on $ip : $openPorts" | Out-File -FilePath $outputFile -Append
            foreach ($port in $openPorts) {
                $banner = Get-Banner -ip $ip -port $port
                "$banner" | Out-File -FilePath $outputFile -Append
                if ($port -eq 80 -or $port -eq 443 -or $port -eq 8080) {
                    $credResult = Test-DefaultCredentials -ip $ip -port $port
                    "$credResult" | Out-File -FilePath $outputFile -Append
                }
            }
            # Run RouterSploit scan
            Run-RouterSploitScan -ip $ip
            # Run Metasploit scan
            Run-MetasploitScan -ip $ip
        } else {
            "No open ports detected on $ip" | Out-File -FilePath $outputFile -Append
        }
    } else {
        "Host $ip is down" | Out-File -FilePath $outputFile -Append
    }
}

Write-Host "Scan complete. Results saved to $outputFile"
"Scan completed at $(Get-Date)" | Out-File -FilePath $outputFile -Append
