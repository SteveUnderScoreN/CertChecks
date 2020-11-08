<#
.SYNOPSIS
    Look for expiring certificates.
.DESCRIPTION
    Connect to a one or more hosts on one or more ports and check if the certificate is due to expire in a specific number of days, the default is 20 days.
    Send emal alerts and create Windows event log entries, where possible, for expiring certificates.
    The script support tab completion using parameters.
.EXAMPLE
    This will query ports 443 and 993 on host "outlook.office365.com" for a certificate expiring in the next 72 days and reporting any issue to "support@mydomain.com"
    Test-CertificateExpiryDate.ps1 -Name "outlook.office365.com" -ExpiryThreshold 72 -AlertToAddress "support@mydomain.com" -port 443, 993
.VERSION
    0.9.8 - Process-MainThread
    2.0.0 - Script wrapper (for logging and alerting)
.TODO
    Check date validation in a different language locales.
    Update the help text.
    Within "Process-MainThread", create 'ignore validation checks' code.
    Within "function Send-EmailAlert", create logic to try port 465 before STARTTLS on port 25 and also cycle through the MX records.
#>
Param
(
    [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
    [Alias("ComputerName", "HostName")]
    [ValidatePattern("^(?!.* )")]
    [string[]]
    $Name,

    [Parameter(Position=1)]
    [validaterange(0, 65535)]
    [int[]]
    $Port = 443,

    [int]
    $ExpiryThreshold = 20,

    [ValidatePattern("^(?!.* )")]
    [mailaddress]
    $AlertFromAddress = $(
                            $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -Property "DNSHostName", "Domain"
                            ($ComputerSystem.DNSHostName + "@" + ($ComputerSystem.Domain).Replace("WORKGROUP","workgroup.local")).ToLower()
                        ),

    [ValidatePattern("^(?!.* )")]
    [mailaddress]
    $AlertToAddress,

    [ValidatePattern("^(?!.* )")]
    [string[]]
    $AlertSmtpServer = $(
                            if ($AlertToAddress)
                            {
                                (Resolve-DnsName -Name $(($AlertToAddress).ToString().Split("@")[1]) -Type MX -ErrorAction SilentlyContinue).NameExchange
                            }
                        ),

    [boolean]
    $IgnoeValidationIssues = $true,

    [ValidateRange(1, 365)]
    [int]
    $LogRetention = 90
)

function Process-MainThread
{
    $HostNames = $Name
    $DestinationPorts = $Port
    Write-Verbose "From address is $AlertFromAddress"
    Write-Verbose "To address is $AlertToAddress"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
    foreach ($HostName in $HostNames)
    {
        foreach ($DestinationPort in $DestinationPorts)
        {
            try
            {
                Write-Verbose "Name is $HostName"
                Write-Verbose "Port is $DestinationPort"
                $Socket = New-Object Net.Sockets.TcpClient($HostName,$DestinationPort)
                $Stream = $Socket.GetStream()
                $SslStream = New-Object System.Net.Security.SslStream $Stream,$false
                $SslStream.AuthenticateAsClient($HostName,$null,"tls11,tls12",$false)
                $Socket.Close()
                $ExpiryDate = [DateTime]::Parse($SslStream.RemoteCertificate.GetExpirationDateString())
                $Date = [DateTime](Get-Date)
                Write-Output "Getting details from a certificate issued by `"$($SslStream.RemoteCertificate.Issuer)`""
                Write-Output "Today's date is $($Date.ToString())"
                Write-Output "Expiry date on $HostName`:$DestinationPort is $($ExpiryDate.ToString())"
                if ($ExpiryThreshold -gt ($ExpiryDate - $Date).Days)
                {
                    Send-EmailAlert -AlertBody "A certificate has been found on $HostName`:$DestinationPort that expires in less than $ExpiryThreshold days." -AlertSubject "Expiring certificate found."
                    Write-EventlogEntry -Message "A certificate has been found on $HostName`:$DestinationPort that expires in less than $ExpiryThreshold days." -EntryType Warning
                    Write-warning "A certificate has been found on $HostName`:$DestinationPort that expires in less than $ExpiryThreshold days."
                }
            }
            catch
            {
                $ScriptError = $true
                if ($error[0].Exception.Message -like "*An existing connection was forcibly closed by the remote host*")
                {
                    Write-Output "`"Access denied`" message received at the network level trying to connect to $HostName`:$DestinationPort."
                }
                elseif ($error[0].Exception.Message -like "*The handshake failed due to an unexpected packet format.*" -or $error[0].Exception.Message -like "*Cannot determine the frame size or a corrupted frame was received*")
                {
                    Write-Output "Handshake failure trying to negotiate a secure socket to $HostName`:$DestinationPort, possibly a non-secure port."
                }
                elseif ($error[0].Exception.Message -like "*An attempt was made to access a socket in a way forbidden by its access permissions*")
                {
                    Write-Output "The local machine firewall has blocked the outbound connection to $HostName`:$DestinationPort."
                }
                else
                {
                    Write-Output "Failed to get certificate details from $HostName`:$DestinationPort."
                }
            }            
        }
    }
}
function Write-EventlogEntry
{
    Param
    (
        [string]
        $Message,

        [ValidateSet("Error","Information","Warning")]
        [string]
        $EntryType = "Error"
    )
    if ($PSVersionTable.PSEdition -eq "Desktop")
    {
        if (-not (Get-WinEvent -ListProvider $ScriptName -ErrorAction SilentlyContinue| Where-Object -FilterScript {$_.LogLinks.LogName -match "Application"}))
        {
            Write-Warning -Message "`"$ScriptName`" doesn't exist as an event source in the Application log."
            try
            {
                New-EventLog -LogName Application -Source $ScriptName -ErrorAction Stop
                Write-Output "Eventlog source `"$ScriptName`" successfully created."
                Write-EventLog -LogName Application -EventId 1000 -Source $ScriptName -EntryType $EntryType -Message $Message
            }
            catch [System.Exception]
            {
                Send-EmailAlert -AlertBody "Failed to create the `"$ScriptName`" eventlog source,`nensure the script is running with administrative priviledges or manually create the source using;`nNew-EventLog -LogName Application -Source `"$ScriptName`""
                Write-Error -Message "Failed to create the `"$ScriptName`" eventlog source,`nensure the script is running with administrative priviledges or manually create the source using;`nNew-EventLog -LogName Application -Source `"$ScriptName`""
            }
        }
        else
        {
            Write-EventLog -LogName Application -EventId 1000 -Source $ScriptName -EntryType $EntryType -Message $Message
        }
    }
    else
    {
        Write-Output "This edition of PowerShell does not natively support writing to Windows event logs."
    }
}
function Send-EmailAlert
{
    Param
    (        
        [string]
        $AlertBody,

        [string]
        $AlertSubject = "An error was encountered in `"$ScriptName`" on host $env:COMPUTERNAME"
    )
    if ($AlertSmtpServer)
    {
        Send-MailMessage -Body $AlertBody -From $AlertFromAddress -SmtpServer $AlertSmtpServer[0] -Subject $AlertSubject -To $AlertToAddress -UseSsl
    }
}

$error.Clear()
$ScriptError = $null
$ScriptName = $MyInvocation.MyCommand
$LogFilePath = "$env:ProgramData\$env:USERDOMAIN\Logs\$ScriptName\"
$LogFile = $LogFilePath + "$ScriptName-$(Get-Date -Format "yyyyMMdd-HHmmss").txt"
try
{
    Start-Transcript -Path $LogFile -IncludeInvocationHeader
    $I = 1
    do
    {
        Start-Sleep -Milliseconds 100
        $I ++
    }
    until ((Test-Path -Path $LogFile) -or ($I -eq 20))
    if (-not (Test-Path -Path $LogFile))
    {
        throw
    }
    if (-not $AlertToAddress)
    {
        Write-Warning -Message "The destination address for email alerts (-AlertToAddress) has not been specified, email alerts are disabled."
        Remove-Variable -Name "AlertSmtpServer" -ErrorAction SilentlyContinue
    }
}
catch
{
    Send-EmailAlert -AlertBody "`"$ScriptName`" on host $env:COMPUTERNAME encountered an error trying to start the transcript log `"$LogFile`"."
    Write-EventlogEntry -Message "`"$ScriptName`" encountered an error trying to start the transcript log `"$LogFile`"."
    Write-Error -Message  "An error was encountered trying to start the transcript log `"$LogFile`"."
    try
    {
        Stop-Transcript
        break
    }
    catch
    {
        break
    }
}
Get-ChildItem -Path "$LogFilePath\*.txt"| Sort-Object -Property "Name"| Select-Object -SkipLast $LogRetention| Remove-Item

. Process-MainThread

if ($error)
{
    Write-Output "All ending error records"
    Write-Output $error
}
if ($ScriptError)
{
        Send-EmailAlert -AlertBody "An error was encountered in `"$ScriptName`" on host $env:COMPUTERNAME, check the log `"$LogFile`"."
        Write-EventlogEntry -Message "An error was encountered in `"$ScriptName`", check the log `"$LogFile`"."
}
Stop-Transcript
