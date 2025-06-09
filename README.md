# RouterScouter

### Approach
1. **RouterSploit**:
   - **Purpose**: An open-source tool for testing routers and embedded devices, with modules for scanning, credential brute-forcing, and exploits (e.g., misconfigurations, known firmware flaws).
   - **Use**: Run the `autopwn` scanner to identify vulnerabilities and attempt basic exploits on detected routers.
   - **Requirements**: Python 3, Git, and RouterSploit installed.
2. **Metasploit**:
   - **Purpose**: A penetration testing framework with modules to scan for services, check CVEs, and exploit vulnerabilities (e.g., weak credentials, unpatched router services).
   - **Use**: Use `msfconsole` to scan for vulnerabilities and attempt basic exploits on common router ports/services.
   - **Requirements**: Metasploit Framework installed (e.g., via [metasploit.com](https://www.metasploit.com/download)).
3. **Ethics**: Ensure explicit, written permission to scan and test the target network/devices. Unauthorized use is illegal and unethical.
4. **Limitations**:
   - PowerShell orchestrates these tools, but they require separate installation and setup.
   - Advanced exploits may need manual tuning in RouterSploit or Metasploit.
   - Firewalls or IDS may detect scans as malicious.

### Prerequisites
- **RouterSploit**:
  - Install Python 3 (from [python.org](https://www.python.org/downloads/)).
  - Install Git (from [git-scm.com](https://git-scm.com/downloads)).
  - Clone RouterSploit: `git clone https://github.com/threat9/routersploit.git`
  - Navigate: `cd routersploit`
  - Install dependencies: `pip install -r requirements.txt`
- **Metasploit**:
  - Install Metasploit Framework (download from [metasploit.com](https://www.metasploit.com/download)).
  - On Windows, use the installer; ensure `msfconsole` is in your PATH or specify its path.
  - Start the Metasploit database: Run `msfdb init` in a terminal if needed (first-time setup).
- **PowerShell**: Run as Administrator for best results.
- **Permissions**: Written consent from the network/device owner.

### Expanded PowerShell Script

```powershell
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
```

### How It Works
1. **Ping Sweep**: Uses `Test-Connection` to find live hosts in the range (e.g., 192.168.1.1 to 192.168.1.254).
2. **Port Scan**: A basic PowerShell scan checks common router ports (22, 23, 80, 443, 8080) as a fallback.
3. **Banner Grabbing**: Retrieves service banners (e.g., HTTP, SSH, Telnet) to identify potential router services.
4. **Default Credentials**: Tests HTTP/HTTPS for common default credentials (e.g., admin:admin).
5. **RouterSploit Integration**:
   - Runs the `scanners/autopwn` module to scan for router vulnerabilities.
   - Uses the `creds/generic/http_default_creds` module to test for default or weak HTTP credentials.
   - Output is logged to the results file.
6. **Metasploit Integration**:
   - Creates a temporary resource script to:
     - Scan ports (`auxiliary/scanner/portscan/tcp`) for confirmation.
     - Detect HTTP service versions (`auxiliary/scanner/http/http_version`) for potential vulnerabilities.
     - Attempt HTTP login brute-forcing (`auxiliary/scanner/http/http_login`) with a wordlist.
   - Runs `msfconsole` with the script and logs results.
7. **Output**: All results (ping, ports, banners, credentials, RouterSploit, Metasploit) are saved to `RouterScanResults.txt`.

### How to Use
1. **Setup**:
   - **RouterSploit**:
     - Install Python, Git, and RouterSploit (see prerequisites).
     - Update `$routerSploitPath` to the RouterSploit directory (e.g., `C:\Path\To\routersploit`).
   - **Metasploit**:
     - Install Metasploit Framework.
     - Update `$msfPath` to the `msfconsole` path (e.g., `C:\Path\To\metasploit-framework\bin\msfconsole.bat`).
     - For the `http_login` module, create or download a wordlist (e.g., user/pass combinations) and update the path in the script (`/path/to/wordlist.txt`). A sample can be found in Metasploit’s default wordlists or online (e.g., SecLists on GitHub).
   - Modify `$network` (e.g., "10.0.0") and `$range` (e.g., 1..10) for your target subnet.
2. **Run**:
   - Open PowerShell as Administrator.
   - Save the script as `RouterVulnScanAdvanced.ps1`.
   - Navigate: `cd C:\Path\To\Script`
   - Execute: `.\RouterVulnScanAdvanced.ps1`
3. **Review**: Check `RouterScanResults.txt` for live hosts, open ports, banners, credential checks, and RouterSploit/Metasploit findings.

### Limitations
- **Dependencies**: Requires RouterSploit and Metasploit installed and configured.
- **Wordlist**: Metasploit’s `http_login` needs a user/password wordlist; you must provide one.
- **Performance**: Running both tools per IP can be slow; consider narrowing the `$range` for testing.
- **Depth**: This uses basic modules; advanced exploits (e.g., specific CVE exploitation) may require manual tuning in RouterSploit or Metasploit.
- **Detection**: Firewalls/IDS may flag scans or exploit attempts.

### Further Enhancements
- **RouterSploit**: Add specific modules (e.g., `exploits/routers/dlink/dns_hijack`) for targeted router brands.
- **Metasploit**: Include vulnerability-specific modules (e.g., `exploit/multi/http/dlink_dir_615h1_auth_bypass`) or CVE checks.
- **Error Handling**: Improve robustness for network timeouts or tool failures.
