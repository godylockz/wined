<#
.PARAMETER pid
    Pid to debug (optional)
.PARAMETER service_name
    Service to debug (required, conflicts with path)
.PARAMETER path
    Path to executable to debug (required, conflicts with path)
.PARAMETER process_name
    Process name to debug (optional)
.PARAMETER launcher
    Launcher to use (optional)
.PARAMETER tcp_port
    TCP port to wait for open (optional)
.PARAMETER udp_port
    UDP port to wait for open (optional)
.PARAMETER commands
    String of windbg commands to be run at startup; separate more than one command with semi-colons (optional)
.EXAMPLE
    Restart the fastback server service and then attach to the fastback server process. Additionally, set a breakpoint as an initial command.
    C:\PS> Set-ExecutionPolicy Unrestricted -Force ; \\tsclient\share\wined\attach.ps1 -service-name fastbackserver -process-name fastbackserver -commands 'bp fastbackserver!recvfrom'
    Restart the sync breeze service and then attach to the sync breeze process.
    C:\PS> Set-ExecutionPolicy Unrestricted -Force ; \\tsclient\share\wined\attach.ps1 -service-name 'Sync Breeze Enterprise'
#>
[CmdletBinding()]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]
    $commands
)

DynamicParam {
    # Set the dynamic parameters' names
    $pid_param = 'pid'
    $svc_param = 'service-name'
    $ps_param = 'process-name'
    $path_param = 'path'
    $launcher_param = 'launcher'
    $tcp_port_param = 'tcp-port'
    $udp_port_param = 'udp-port'

    # Create the dictionary
    $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

    # Function to create and set parameters' attributes
    function CreateRuntimeParameter ($paramName) {
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $AttributeCollection.Add($ParameterAttribute)

        if ($paramName -eq 'service-name') {
            $svc_set = Get-Service | Select-Object -ExpandProperty Name
            $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($svc_set)
            $AttributeCollection.Add($ValidateSetAttribute)
        }

        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($paramName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($paramName, $RuntimeParameter)
    }

    # Create and set attributes for each dynamic parameter
    CreateRuntimeParameter $pid_param
    CreateRuntimeParameter $svc_param
    CreateRuntimeParameter $ps_param
    CreateRuntimeParameter $path_param
    CreateRuntimeParameter $launcher_param
    CreateRuntimeParameter $tcp_port_param
    CreateRuntimeParameter $udp_port_param

    return $RuntimeParameterDictionary
}

begin {
    function WaitForPorts {
        param (
            [int]$tcp_port,
            [int]$udp_port
        )
        if ($tcp_port) {
            $startTime = Get-Date
            $initialCheck = Get-NetTCPConnection -LocalPort $tcp_port -State Listen -ErrorAction SilentlyContinue
            if ($null -eq $initialCheck) {
                Write-Host "[*] Waiting for TCP port $tcp_port to become available ..."
                while ($null -eq (Get-NetTCPConnection -LocalPort $tcp_port -State Listen -ErrorAction SilentlyContinue)) {
                    Start-Sleep -Seconds 1
                }
                $duration = (Get-Date) - $startTime
                Write-Host "[*] TCP port $tcp_port is now listening. It took $($duration.TotalSeconds) seconds to open."
            }
        }
        if ($udp_port) {
            $startTime = Get-Date
            $initialCheck = Get-NetUDPEndpoint -LocalPort $udp_port -ErrorAction SilentlyContinue
            if ($null -eq $initialCheck) {
                Write-Host "[*] Waiting for UDP port $udp_port to become available ..."
                while ($null -eq (Get-NetUDPEndpoint -LocalPort $udp_port -ErrorAction SilentlyContinue)) {
                    Start-Sleep -Seconds 1
                }
                $duration = (Get-Date) - $startTime
                Write-Host "[*] UDP port $udp_port is now listening. It took $($duration.TotalSeconds) seconds to open."
            }
        }
    }

    function ProcessReboot {
        param (
            [string]$path,
            [string]$launcher,
            [int]$tcp_port,
            [int]$udp_port
        )

        # Find process by $pname
        $pname = (Get-Item $path).BaseName
        do {
            $existing_processes = Get-Process -Name $pname -ErrorAction SilentlyContinue
            if ($existing_processes) {
                Write-Host "[*] Stopping process: $pname @ $path"
                $null = Stop-Process -Name $pname -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
            }
        } while ($existing_processes.Count -gt 0)

        # Start process
        $target_path = if ($null -ne $launcher -and '' -ne $launcher) { $launcher } else { $path }
        $path_validate = Test-Path $target_path
        if (-not $path_validate) {
            Write-Error "$target_path does not exist" -ErrorAction Stop
        }
        Write-Host "[*] Starting process: $pname @ $target_path"
        $null = Unblock-File -Path $target_path
        $null = Start-Process -FilePath $target_path -PassThru

        # Wait for process to start
        do {
            Start-Sleep -Seconds 1
            $existing_processes = Get-Process -Name $pname -ErrorAction SilentlyContinue
        } until ($existing_processes.Count -gt 0)

        # Simulate key presses
        if ($pname -eq "KNet") {
            Write-Host "[*] $pname simulating key presses.."
            [Windows.Forms.SendKeys]::SendWait("%fo") # Alt + F + O
            Start-Sleep -Milliseconds 500
            [Windows.Forms.SendKeys]::SendWait("%f") # Alt + F
            Start-Sleep -Milliseconds 1000
            [Windows.Forms.SendKeys]::SendWait("+({END}){DEL}") # Shift + End & Delete
            Start-Sleep -Milliseconds 250
            [Windows.Forms.SendKeys]::SendWait("C:\Installers\seh_overflow\extra_mile\02{ENTER}")
            Start-Sleep -Milliseconds 250
            [Windows.Forms.SendKeys]::SendWait("index.html{ENTER}")
            Start-Sleep -Milliseconds 250
            [Windows.Forms.SendKeys]::SendWait("index.html{ENTER}")
        }

        # Wait for ports to be open
        $null = WaitForPorts -tcp_port $tcp_port -udp_port $udp_port

        return $pname
    }

    function ServiceReboot {
        param (
            [string]$service_name,
            [int]$tcp_port,
            [int]$udp_port
        )

        # Find service
        $service = Get-Service -Name $service_name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            # Stop service
            if ($service.Status -eq 'Running') {
                Write-Host "[*] Stopping service: $service_name"
                $null = Stop-Service -Name $service_name -ErrorAction SilentlyContinue
                do {
                    Start-Sleep -Seconds 1
                    $service = Get-Service -Name $service_name
                } until ($service.Status -ne 'Running')
            }

            # Start service
            Write-Host "[*] Starting service: $service_name"
            $before_processes = Get-Process
            $null = Start-Service -Name $service_name

            # Wait for service to start
            do {
                Start-Sleep -Seconds 1
                $service = Get-Service -Name $service_name
            } until ($service.Status -eq 'Running')
            $after_processes = Get-Process
        }
        else {
            Write-Error "Service not found: $service_name"
        }

        # Identify process name that was spawned from the service
        $new_processes = $after_processes | Where-Object { $_.ProcessName -notin $before_processes.ProcessName }
        if ($new_processes.Count -eq 0) {
            Write-Host "[*] No new process detected."
        }
        else {
            $pname = $new_processes[0].ProcessName
            Write-Host "[*] New process detected: $pname"
        }

        # Wait for ports to be open
        $null = WaitForPorts -tcp_port $tcp_port -udp_port $udp_port

        return $pname
    }

    # Check if windbg is up
    $windbg = Get-Process -Name "windbg" -ErrorAction SilentlyContinue
    if ($windbg.Count -gt 0) {
        Write-Host "[*] Killing existing windbg processes"
        Stop-Process -Name "windbg" -Force
        Start-Sleep -Seconds 1
    }

    # Inputs
    $process_pid = $PsBoundParameters[$pid_param]
    $service_name = $PsBoundParameters[$svc_param]
    $path = $PsBoundParameters[$path_param]
    $process_name = $PsBoundParameters[$ps_param]
    $launcher = $PsBoundParameters[$launcher_param]
    $tcp_port = $PSBoundParameters[$tcp_port_param]
    $udp_port = $PSBoundParameters[$udp_port_param]

    # Start service or executable
    $service_entered = $null -ne $service_name -and '' -ne $service_name
    $process_entered = ($null -ne $path -and '' -ne $path) -or $null -ne $launcher -and '' -ne $launcher
    if ($service_entered -and $process_entered) {
        Write-Error "Cannot specify both -service-name and -path arguments. Choose one." -ErrorAction Stop
    }
    elseif ($service_entered) {
        $pname = ServiceReboot -service_name $service_name -tcp_port $tcp_port -udp_port $udp_port
    }
    elseif ($process_entered) {
        $pname = ProcessReboot -path $path -launcher $launcher -tcp_port $tcp_port -udp_port $udp_port
    }
    elseif ($null -ne $process_pid -and '' -ne $process_pid) {
        $process = Get-Process -Id $process_pid -ErrorAction SilentlyContinue
        if ($process.Count -eq 0) {
            Write-Error "Unable to find process by pid" -ErrorAction Stop
        }
        $pname = $process[0].ProcessName
        Write-Host "[*] Process identified: $pname"
    }
    if ($null -ne $process_name -and '' -ne $process_name) {
        Write-Host "[*] Process name provided: $process_name"
    }
    elseif ($null -ne $pname -and '' -ne $pname) {
        Write-Host "[*] Process name found: $pname"
        $process_name = $pname
    }
}

process {
    # Operating-system dependency
    if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit") {
        $program_files = "C:\Program Files (x86)"
    }
    else {
        $program_files = "C:\Program Files"
    }

    while ($true) {
        # Error-checking
        if (-not $process) {
            if ($null -eq $process_name -or '' -eq $process_name) {
                Write-Error "No process_name provided. Use -process-name to specify the process to attach." -ErrorAction Stop
            }
            $process = Get-Process -Name $process_name -ErrorAction SilentlyContinue
        }
        if (-not $process) {
            Write-Error "Supplied -process-name $process_name not found" -ErrorAction Stop
        }
        if ($process.Count -gt 1) {
            Write-Error "Multiple processes found with the same name: $process_name" -ErrorAction Stop
        }

        # Start windbg
        Write-Host "[*] Attaching windbg to $($process.Name) @ $($process.Id)"
        $cmd_args = "-p $($process.Id) "
        if (-not (Test-Path "$program_files\Windows Kits\10\Debuggers\x86\winext\pykd.dll")) {
            if ($commands) {
                $cmd_args += "-c '.load pykd.pyd; $commands' "
            }
            else {
                $cmd_args += "-c '.load pykd.pyd;g' "
            }
        }
        else {
            if ($commands) {
                $cmd_args += "-c '.load pykd; $commands' "
            }
            else {
                $cmd_args += "-c '.load pykd;g' "
            }
        }
        #$cmd_args += "-WF c:\windbg_custom.wew " # Workspace
        $null = Start-Process -Wait -FilePath "$program_files\Windows Kits\10\Debuggers\x86\windbg.exe" -Verb RunAs -ArgumentList $cmd_args

        # Reboot process or service when terminated
        Write-Host "[!] Detected crash..."
        Start-Sleep -Seconds 2
        if ($null -ne $service_name -and '' -ne $service_name) {
            $null = ServiceReboot -service_name $service_name -tcp_port $tcp_port -udp_port $udp_port
        }
        if ($null -ne $path -and '' -ne $path) {
            $null = ProcessReboot -path $path -launcher $launcher -tcp_port $tcp_port -udp_port $udp_port
        }
        $process = $null
    }
}
