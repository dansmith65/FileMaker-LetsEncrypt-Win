<#
.SYNOPSIS
	Get an SSL certificate from Let's Encrypt and install it on FileMaker Server.

.PARAMETER InstallDependencies
	Install all dependent libraries; restart may be required if .NET is updated. Run this once
	before using this script for the first time. This action is performed if no parameters sent to
	the script.
	Include the -Force parameter to update dependencies.

.PARAMETER Setup
	Store new domains and emails, or modify them, then get and install a certificate. This is
	intended to be run with a user at the console so they can enter fmsadmin credentials, if needed.

.PARAMETER Domains
	Array of domain(s) for which you would like an SSL Certificate. Let's Encrypt will peform
	separate validation for each of the domains, so be sure that your server is reachable at all of
	them before attempting to get a certificate. 100 domains is the max.

.PARAMETER Emails
	Contact email address(es) to your real email address so Let's Encrypt can contact you if there
	are any problems (or if the certificate is about to expire).

.PARAMETER Renew
	Renew the most recently used certificate.

.PARAMETER InstallCertificate
	Installs the most recently retrieved certificate. Useful if a certificate was successfully
	retrieved, but something failed before it was installed.

.PARAMETER Staging
	Use Let's Encrypt Staging server and don't restart FileMaker Server service. Use this option for
	testing/setup, but beware that the certificate will be imported, so you would either need to
	restore the old certificate or call this script again without this parameter to install a
	production certificate.

.PARAMETER Force
	When renewing, force renewal, even if certificate is not recommended for renewal yet.
	When using Staging parameter, force FMS to restart.

.PARAMETER ScheduleTask
	Schedule a task via Windows Task Scheduler to renew the certificate automatically.

.PARAMETER IntervalDays
	When scheduling a task, specify an interval to repeat on. Default is 63 days because:
		- Let's Encrypt's recommendation is to renew when a certificate has a third of it's total
		  lifetime left.
		- if interval is divisible by 7, then it will always occur on the same day of the week

.PARAMETER Time
	When scheduling a task, specify a time of day to run it. Can optionally specify the exact
	date/time of the first schedule.

.PARAMETER ConfigureEmail
	Store credentials and SMTP info so this script can send logs when it runs.

.NOTES
	File Name:   GetSSL.ps1
	Author:      Daniel Smith dan@filemaker.consulting
	Revised:     2020-03-05
	Version:     2.0.0-alpha10

.LINK
	https://github.com/dansmith65/FileMaker-LetsEncrypt-Win

.LINK
	http://bluefeathergroup.com/blog/how-to-use-lets-encrypt-ssl-certificates-with-filemaker-server/

.LINK
	https://github.com/rmbolger/Posh-ACME/wiki/%28Advanced%29-Manual-HTTP-Challenge-Validation

#TODO: review/correct all these examples:
.EXAMPLE
	.\GetSSL.ps1 test.com user@test.com

	Simplest call with domain to sign listed first and email second.

.EXAMPLE
	.\GetSSL.ps1 test.com, sub.example.com user@test.com

	Multiple domains can be listed, separated by commas.

.EXAMPLE
	.\GetSSL.ps1 -d test.com -e user@test.com

	Can use short-hand parameter names.

.EXAMPLE
	.\GetSSL.ps1 -Domains test.com -Emails user@test.com

	Or full parameter names.

.EXAMPLE
	.\GetSSL.ps1 test.com user@test.com

	Use if you installed FileMaker Server in a non-default path.
	Must end in a backslash.

.EXAMPLE
	.\GetSSL.ps1 test.com user@test.com -Confirm:$False

	Don't ask for confirmation; use the -Confirm:$False parameter when called from a scheduled task.
	To have this script run silently, it must also be able to perform fmsadmin.exe without asking for username and password. There are two ways to do that:
		1. Add a group name that is allowed to access the Admin Console and run the script as a user that belongs to the group.
		2. Hard-code the username and password into this script. (NOT RECOMMENDED)

.EXAMPLE
	.\GetSSL.ps1 test.com user@test.com -WhatIf

	Display the inputs, then exit; use to verify you passed parameters in the correct format

.EXAMPLE
	.\GetSSL.ps1 test.com user@test.com -ScheduleTask

	Schedule a task via Windows Task Scheduler to renew the certificate every 63 days.

.EXAMPLE
	.\GetSSL.ps1 test.com user@test.com -ScheduleTask -IntervalDays 70

	Schedule a task via Windows Task Scheduler to renew the certificate every 70 days

.EXAMPLE
	.\GetSSL.ps1 test.com user@test.com -ScheduleTask -Time 1:00am

	Schedule a task via Windows Task Scheduler to renew the certificate every 63 days at 1:00am.

.EXAMPLE
	.\GetSSL.ps1 test.com user@test.com -ScheduleTask -Time "1/1/2018 1:00am"

	Schedule a task via Windows Task Scheduler to renew the certificate every 63 days starting Jan 1st 2018 at 1:00am.
#>


[cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName='InstallDependencies')]
Param(
	[Parameter(ParameterSetName='InstallDependencies')]
	[switch] $InstallDependencies,


	[Parameter(ParameterSetName='Setup')]
	[switch] $Setup,

	[Parameter(ParameterSetName='Setup',Mandatory=$True,Position=1)]
	[Alias('d')]
	[string[]] $Domains,

	[Parameter(ParameterSetName='Setup',Mandatory=$True,Position=2)]
	[Alias('e')]
	[string[]] $Emails,


	[Parameter(ParameterSetName='InstallCertificate')]
	[switch] $InstallCertificate,


	[Parameter(ParameterSetName='ScheduleTask')]
	[Alias('s')]
	[switch] $ScheduleTask,

	[Parameter(ParameterSetName='ScheduleTask')]
	[Alias('i')]
	[string] $IntervalDays=63,

	[Parameter(ParameterSetName='ScheduleTask')]
	[Alias('t')]
	[DateTime] $Time="4:00am",


	[Parameter(ParameterSetName='Renew')]
	[switch] $Renew,


	[Parameter(ParameterSetName='ConfigureEmail')]
	[switch] $ConfigureEmail,


	[switch] $Staging,
	[switch] $Force
)

<# Exit immediately on error #>
$ErrorActionPreference = "Stop"


#########################################################################################################################
# Functions

function Backup-File {
	Param(
		[Parameter(Position=1)]
		[string]$path,

		[string]$BackupDirectory = $(Join-Path $FMSPath ('CStore\Backup\' + $Start.ToString("yyyy-MM-dd_HHmmss") +"\"))
	)
	If ( -not (Test-Path $BackupDirectory) ) { New-Item -ItemType directory -Path $BackupDirectory | Out-Null }
	Write-Output "backing up $(Split-Path $path -Leaf) to $BackupDirectory"
	Copy-Item $path $BackupDirectory
}

function Get-ScriptLineNumber { return $MyInvocation.ScriptLineNumber }

function Send-Email ($subject, $body) {
	$result = ""
	try {
		$credentials = Get-StoredCredential -Target "GetSSL Send Email"
		if ($credentials) {
			$smtpInfo = (Get-StoredCredential -AsCredentialObject -Target "GetSSL Send Email").Comment | ConvertFrom-Json
			if (! $Emails) {
				$Emails = ((Get-PAAccount).contact).Replace('mailto:','')
			}
			if ($smtpInfo) {
				Send-MailMessage -Subject $subject -Body $body -Encoding UTF8 -Credential $credentials -To $Emails `
					-From $smtpInfo.from `
					-SmtpServer $smtpInfo.server `
					-Port $smtpInfo.port `
					-UseSsl:$smtpInfo.useSSL
				$result = "email sent"
			} else {
				$result = "email could not be sent; no credentials loaded"
			}
		}
		$credentials = $null
	}
	catch {
		# don't let this stop the script from continuing
		$result = ($_ | Out-String)
		$result += "Stack Trace:`r`n"
        $result += $_.ScriptStackTrace
	}
	return $result
}

function Install-Dependencies {
	$PackageProvider = Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction:Ignore
	if (-not($PackageProvider) -or ($PackageProvider.Version -lt [System.Version]"2.8.5.201")) {
		Write-Output "installing NuGet package provider"
		Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
	}

	if ((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -lt 461308) {
		if ($PSCmdlet.ShouldProcess(
			"[OPTIONAL] Update Dot Net Framework to latest version, so the main branch of Posh-ACME can be used? Restart will likely be required which you can choose to do later, but won't be able to proceed with certificate installation until you do.",
			"[OPTIONAL] Update Dot Net Framework to latest version, so the main branch of Posh-ACME can be used? Restart will likely be required which you can choose to do later, but won't be able to proceed with certificate installation until you do.",
			"Update Dot Net Framework?"
		)) {
			# https://docs.microsoft.com/en-us/dotnet/framework/deployment/deployment-guide-for-developers
			$dlurl = 'https://go.microsoft.com/fwlink/?LinkId=2085155'
			$installerPath = Join-Path $env:TEMP ndp48-web.exe
			Invoke-WebRequest $dlurl -OutFile $installerPath
			Start-Process -FilePath $installerPath -Wait -Args "/passive /promptrestart"
			# Am assuming the computer will have to restart and this script run again at this point
		}
	}

	if ((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -lt 461308) {
		if ($Force -or -not(Get-Module -Listavailable -Name Posh-ACME.net46)) {
			Write-Output "Install Posh-ACME.net46"
			Install-Module -Name Posh-ACME.net46 -AllowClobber -Confirm:$false -Force
		}
	} else {
		if ($Force -or -not(Get-Module -Listavailable -Name Posh-ACME)) {
			Write-Output "Install Posh-ACME"
			Install-Module -Name Posh-ACME -AllowClobber -Confirm:$false -Force
		}
	}

	if ($Force -or -not(Get-Module -Listavailable -Name CredentialManager)) {
		Write-Output "Install CredentialManager"
		Install-Module -Name CredentialManager -AllowClobber -Confirm:$false -Force
	}
}

function Install-Cert {
	<# validate FMSPath #>
	if (-not(Test-Path $fmsadmin)) {
		throw "fmsadmin could not be found at: '$fmsadmin', please check the FMSPath parameter: '$FMSPath'"
	}

	Write-Output "Confirming access to fmsadmin.exe: ______________________________________________"
	<# FileMaker Server must be started to import a certificate (and to confirm access) #>
	if ((Get-Service "FileMaker Server").Status  -ne "Running") {
		Write-Output "FileMaker Server service was not running, it will be started now"
		Start-Service "FileMaker Server"
		Start-Sleep 2 # give the service a few seconds to start before testing if fmserver is running
	}
	if (-not(Get-Process fmserver -ErrorAction:Ignore)) {
		Write-Output "FileMaker Server process was not running, it will be started now"
		Invoke-FMSAdmin start, server -Timeout 90
		Start-Sleep -Seconds 1
		if (-not(Get-Process fmserver -ErrorAction:Ignore)) {
			throw ("server process still not running after starting it; check FileMaker logs to see what's wrong")
		}
		if ($externalAuth) {
			# Sometimes external authentication fails right after starting server; trigger that failure here
			Test-FMSAccess
		}
	}
	
	# stored credentials take precedence over external authentication
	$fmsCredential = Get-StoredCredential -Target "GetSSL FileMaker Server Admin Console" -AsCredentialObject
	if ($fmsCredential) {
		$username = $fmsCredential.UserName
		$password = $fmsCredential.Password
		if ($username -and $password) {
			$userAndPassParamString = "-u ""$username"" -p ""$password"""
			Write-Output "retrieved stored credentials"
			$FMAccessConfirmed = Test-FMSAccess
		}
		$fmsCredential = $username = $password = $null
	} else {
		Write-Output "no credentials were stored"
	}

	if (! $FMAccessConfirmed) {
		$externalAuth = Test-FMSAccess
		if (! $externalAuth) {
			# I don't know, but I suspect fmsadmin occasionally needs some time here, or throttles logins
			Start-Sleep -Seconds 1
			<# Sometimes fmsadmin asks for a password even if it's configured properly to use external
			   authentication, check again to be sure it's for real.
			   https://community.filemaker.com/message/803496 #>
			$externalAuth = Test-FMSAccess
		}
		if ($externalAuth) {
			$FMAccessConfirmed = $true
			Write-Output "external authentication credentials used"
		}
	}

	if ($FMAccessConfirmed) {
		Write-Output "confirmed"
	} elseif (Test-IsInteractiveShell) {
		Write-Output "no access via stored credentials or external authentication"
		Write-Output "A window will open where you can securely enter your fmsadmin login. Sometimes it takes a moment to open."
		while ($True) {
			$fmsCredential = Get-Credential -Message "FileMaker Server Admin Console Sign In" | New-StoredCredential -Target "GetSSL FileMaker Server Admin Console" -Persist LocalMachine
			if ($fmsCredential) {
				$username = $fmsCredential.UserName
				$password = $fmsCredential.Password
				$userAndPassParamString = "-u ""$username"" -p ""$password"""
				$fmsCredential = $username = $password = $null
				$FMAccessConfirmed = Test-FMSAccess
				if ($FMAccessConfirmed) {
					break
				} else {
					Write-Output "That account didn't work, please try again."
				}
			} else {
				throw ("Permissions not setup to allow performing fmsadmin.exe without entering username and password.")
			}
		}
			
	} else {
		throw ( "no access! Must be able to perform fmsadmin without entering user/pass when this script is not run interactively" )
	}
	Write-Output ""


	Write-Output "Get certificate: ________________________________________________________________"
	$certObj = Get-PACertificate
	if (! $certObj) { throw "no certificate found" }

	Write-Output "Export the private key"
	$keyPath = Join-Path $FMSPath 'CStore\serverKey.pem'
	if (Test-Path $keyPath) {
		Backup-File $keyPath
		Remove-Item $keyPath
	}
	Copy-Item ($certObj.KeyFile) $keyPath
	Write-Output ""

	$serverCustomPath = Join-Path $FMSPath 'CStore\serverCustom.pem'
	if (Test-Path $serverCustomPath) {
		Backup-File $serverCustomPath
		Write-Output ""
	}


	Write-Output "Import certificate via fmsadmin: ________________________________________________"
	Invoke-FMSAdmin certificate, import, """$($certObj.CertFile)""", --intermediateCA, """$($certObj.FullChainFile)""", -y
	Write-Output ""


	Write-Output "Stop FileMaker Server: __________________________________________________________"
	if ($Staging -and !$Force) {
		Write-Output "skipped because -Staging parameter was provided"
	} else {
		$WPEWasRunning = Get-Process fmscwpc -ErrorAction:Ignore
		Write-Output "check if files are open first"
		try { $FilesWereOpen = Invoke-FMSAdmin list, files -Timeout 5 }
		catch [System.TimeoutException] {
			Write-Output "failed to list files within 5 seconds"
			Write-Output "assume files are open since it's safer than the alternative"
			$FilesWereOpen = $true
		}
		if ($FilesWereOpen) {
			Write-Output "files are open"
		} else {
			Write-Output "no files open"
		}
		Write-Output "now stop server"
		<# Try to stop server multiple times, if necessary. #>
		$retries = 3
		$timeout = 90
		while ($true) {
			$retries--
			try {
				Write-Output ("with timeout of $timeout seconds, starting at {0}..." -f (Get-Date).ToLongTimeString())
				# first timeout is sent to fmsadmin, to give users this amount of time to close files before they are forcibly closed
				# second timeout is to forcibly stop the fmsadmin command in case it hangs
				Invoke-FMSAdmin stop, server, -y, -t, $timeout -Timeout ($timeout + 20)
				break
			}
			catch [System.TimeoutException] {
				if ($retries -gt 0) {
					Write-Output "  timed out, $retries attempt(s) left before aborting"
					$timeout *= 2
				} else { throw }
			}
			catch [System.ApplicationException] {
				if ($_.Exception.Message.StartsWith("fmsadmin")) {
					if (($_.Exception.Data.ExitCode) -eq 10002) {
						if ($retries -gt 0) {
							Write-Output "  fmsadmin timed out, $retries attempt(s) left before aborting"
							$timeout *= 2
						} else { throw }
					}
					elseif (($_.Exception.Data.ExitCode) -eq 10502) {
						Write-Output "10502 (Host unreachable) occurs when the service or server is stopped"
						break
					} else { throw }
				} else { throw }
			}
		}
		$mustStartServer = $True
	}
	Write-Output ""


	Write-Output "Restart the FMS service: ________________________________________________________"
	if ($Staging -and !$Force) {
		Write-Output "skipped because -Staging parameter was provided"
	} else {
		Restart-Service "FileMaker Server"
	}
	Write-Output ""


	<# Just in case server isn't configured to start automatically #>
	Write-Output "Start FileMaker Server: _________________________________________________________"
	if ($Staging -and !$Force) {
		Write-Output "skipped because -Staging parameter was provided"
	} else {
		<# Try to start server multiple times, if necessary. I'm not sure, but I suspect fmsadmin
		   sometimes asks for credentials here, which causes the script to fail #>
		$retries = 3
		$timeout = 90
		while ($true) {
			$retries--
			try {
				Write-Output ("with timeout of $timeout seconds, starting at {0}..." -f (Get-Date).ToLongTimeString())
				Invoke-FMSAdmin start, server -Timeout $timeout
				break
			}
			catch [System.TimeoutException] {
				if ($retries -gt 0) {
					Write-Output "  timed out, $retries attempt(s) left before aborting"
					$timeout *= 2
				} else { throw }
			}
			catch [System.ApplicationException] {
				# NOTE: Error: 10007 (Requested object does not exist) occurs when service is stopped
				if ($_.Exception.Message.StartsWith("fmsadmin") -and ($_.Exception.Data.ExitCode) -eq 10006) {
					Write-Output "(If server is set to start automatically, error 10006 is expected)"
					break
				} else { throw }
			}
		}

		$mustStartServer = $False
		if ($WPEWasRunning -and -not(Get-Process fmscwpc -ErrorAction:Ignore)) {
			<# NOTE: this will only work as expected from 64 bit PowerShell since Get-Process only lists processes running the same bit depth as PowerShell #>
			Write-Output "start WPE because it was running before FMS was stopped, but isn't now:"
			Invoke-FMSAdmin start, wpe
			Write-Output "done starting WPE"
		}
		if ($FilesWereOpen) {
			Write-Output "files were open, confirm access to fmsadmin"
			<# Confirm FMAccess again, since it can ask for a password again after starting
			   server. Do it twice; first time will likely fail, second time should succeed.
			   https://community.filemaker.com/thread/191306 #>
			Start-Sleep -Seconds 3 # if the next check is too soon after starting server, it will fail
			$FMAccessConfirmedAfterRestart = Test-FMSAccess
			if (-not ($FMAccessConfirmedAfterRestart)) {
				# NOTE: I don't know, but I suspect fmsadmin occasionally needs some time here, or throttles logins
				Start-Sleep -Seconds 1
				<# Sometimes fmsadmin asks for a password even if it's configured properly to use external
				   authentication, check again to be sure it's for real.
				   https://community.filemaker.com/message/803496 #>
				$FMAccessConfirmedAfterRestart = Test-FMSAccess
			}
			if ($FMAccessConfirmedAfterRestart) {
				Write-Output "check if files are open now"
				try { $FilesAreOpen = Invoke-FMSAdmin list, files -Timeout 5 }
				catch [System.TimeoutException] {
					Write-Output "failed to list files within 5 seconds"
					Write-Output "assume files are not open since it's safer than the alternative"
					$FilesAreOpen = $false
				}
				if(-not($FilesAreOpen)) {
					Write-Output "open files because they were open before FMS was stopped, but aren't now:"
					Invoke-FMSAdmin open
				} else {
					Write-Output "they are"
				}
			} else {
				throw "could not connect to fmsadmin"
			}
		}
	}
	Write-Output "done"
	Write-Output ""
}

function Invoke-FMSAdmin {
<#
	.SYNOPSIS
		Calls fmsadmin.exe with specified parameters and will prevent it from hanging a script
		if it waits for user input.

	.OUTPUTS
		Returns standard output from fmsadmin.

		fmsadmin errors will throw an exception which contains the exit code.

	.PARAMETER Parameters
		List of parameters to send to fmsadmin. Parameters with a space must be a quoted string.

	.PARAMETER Timeout
		Seconds to wait for the process before failing with an error.
		Will throw [System.TimeoutException] if fmsadmin does not complete within this time.

	.EXAMPLE
		Invoke-FMSAdmin list, files

	.EXAMPLE
		Invoke-FMSAdmin list, files -Timeout 5

	.EXAMPLE
		Invoke-FMSAdmin open, """File With Spaces"""
		Invoke-FMSAdmin open, """$fileNameWithSpaces"""

	.EXAMPLE
		Invoke-FMSAdmin stop, server, -t, 30
		Invoke-FMSAdmin stop, server, "-t 30"

		Either of these formats will work

	.EXAMPLE
		try { Invoke-FMSAdmin bad, command }
		catch [System.ApplicationException] {
			if ($_.Exception.Message.StartsWith("fmsadmin")) {
				$_.Exception.Data.ExitCode
			} else {
				# was not an fmsadmin-specific exception, so throw it back
				throw
			}
		}
#>
	Param(
		[Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=1)]
		[string[]] $Parameters,
		
		[int]$Timeout = 30
	)
	# https://stackoverflow.com/a/36539226
	$pinfo = New-Object System.Diagnostics.ProcessStartInfo
	$pinfo.FileName = $fmsadmin
	$pinfo.RedirectStandardError = $true
	$pinfo.RedirectStandardOutput = $true
	$pinfo.UseShellExecute = $false # must be false to redirect IO streams
	$pinfo.Arguments = "$Parameters $userAndPassParamString"
	$pinfo.CreateNoWindow = $true

	$p = New-Object System.Diagnostics.Process
	$p.StartInfo = $pinfo

	[Void]$p.Start()

	$stdoutTask = $p.StandardOutput.ReadToEndAsync();
	$stderrTask = $p.StandardError.ReadToEndAsync();

	[Void]$p.WaitForExit($Timeout * 1000)

	if (! $p.HasExited) {
		$p.Kill()
		$p.Close()
		throw [System.TimeoutException] "fmsadmin did not complete within timeout of $Timeout seconds`n$fmsadmin $Parameters"
	}

	$stdout = $stdoutTask.Result;
	$stderr = $stderrTask.Result;

	if ($p.ExitCode) {
		Write-Verbose "$fmsadmin $Parameters" -Verbose
		if ($stderr) {
			# NOTE: I don't think fmsadmin uses stderr, but I'd rather include it to be safe
			Write-Host "stderr: $stderr"
		}
		if ($stdout) {Write-Verbose $stdout -Verbose}

		$e = [System.ApplicationException]::New("fmsadmin exit code: " + $p.ExitCode)
		$e.Data.Add('ExitCode', $p.ExitCode)
		throw $e
	}

	if ($stderr) {
		# NOTE: I don't think fmsadmin uses stderr, but I'd rather include it to be safe
		Write-Verbose "$fmsadmin $Parameters" -Verbose
		Write-Error "stderr: $stderr"
	}
	return $stdout
}

function New-Cert {
	if (! $account) {
		Write-Output "Account Setup ___________________________________________________________________"
		$accounts = Get-PAAccount -List -Contact $Emails -Status valid
		if ($accounts) {
			# valid account(s) already exist for this email
			if ($accounts -is [array]) {
				Write-Output "multiple accounts found; selected the last one"
				$account = $accounts[-1]
			} else {
				Write-Output "selected an existing account"
				$account = $accounts
			}
			Set-PAAccount -ID $account.id
		} else {
			Write-Output "create new account"
			$account = New-PAAccount -Contact $Emails -AcceptTos
		}
		($account | Select-Object id, status, contact, location | Format-List | Out-String).Trim()
		Write-Output ""
	}


	Write-Output "Create an Order _________________________________________________________________"
	New-PAOrder $Domains -Force:$Force
	$order = Get-PAOrder
	if (-not $order) {
		throw "No order found. This should never be able to happen."
	} elseif ($order.status -eq "valid") {
		Write-Output "Order has already been completed; previous certificate will be used."
		Write-Output "Use the -Force parameter to always issue a new certificate here."
		Write-Output ""
		return
	}
	Write-Output ""


	Write-Output "Authorizations and Challenges ___________________________________________________"
	$acmeChallengePath = Join-Path $FMSPath 'HTTPServer\conf\.well-known\acme-challenge'
	if (! (Test-Path $acmeChallengePath)) {
		Write-Output "Create acme-challenge directory"
		(New-Item -Path $acmeChallengePath -ItemType Directory).ToString().Trim()
	}

	$webConfigPath = Join-Path $acmeChallengePath "web.config"
	if (! (Test-Path $webConfigPath)) {
		Write-Output "Create web.config file"
		'<configuration><system.webServer><staticContent><remove fileExtension="." /><mimeMap fileExtension="." mimeType="text/plain" /></staticContent></system.webServer></configuration>' | Out-File $webConfigPath
	}

	Write-Output "Create challenge file(s)"
	$auths = $order | Get-PAAuthorizations
	foreach ($auth in $auths) {
		$path = Join-Path $acmeChallengePath $auth.HTTP01Token
		$body = Get-KeyAuthorization $auth.HTTP01Token $account
		$body | Out-File -Encoding ascii -FilePath $path
	}

	# Send all challenges at once
	$auths.HTTP01Url | Send-ChallengeAck

	Write-Output "Wait for LE to validate"
	# https://tools.ietf.org/html/rfc8555#section-7.1.6
	# Once the authorization is in the "valid" state, it can expire ("expired"), be deactivated by the client ("deactivated", see Section 7.5.2), or revoked by the server ("revoked")
	Write-Output (Get-Date).ToLongTimeString()
	$timeout = New-TimeSpan -Minutes 1
	$sw = [diagnostics.stopwatch]::StartNew()
	do {
		if ($sw.elapsed -gt $timeout) {
			$auths
			throw ("authorization was not processed before timing out")
		}

		<# I tested with 1ms sleep and it was valid on the first iteration,
		   but to be curtious to LE's server's, I set it to sleep for 1 second #>
		Start-Sleep -Seconds 1
		$auths = $order | Get-PAAuthorizations

		# they start as pending then move to processing, then valid or invalid
		$pending = $auths | Where-Object {($_.status -eq "pending") -or ($_.status -eq "processing")}
		
        Write-Progress "Wait for LE to validate" -SecondsRemaining $timeout.Subtract($sw.Elapsed).TotalSeconds
	}
	until (! $pending)
	Write-Progress "Wait for LE to validate" -Complete
	Write-Output "completed in $([math]::Round($sw.Elapsed.TotalSeconds)) seconds"
	$notValid = $auths | Where-Object status -ne "valid"
	$order = Get-PAOrder -Refresh
	if ($notValid) {
		Write-Output ""
		($notValid | Format-List | Out-String).Trim()
		($notValid.challenges.error | Format-List | Out-String).Trim()
		($order | Format-List | Out-String).Trim()
		throw ("unexpected status value")
	}
	if (($order.status -ne "ready") -and ($order.status -ne "valid")) {
		($order | Format-List | Out-String).Trim()
		throw ("order wasn't ready or valid, but should have been at this point in the script")
	}
	Write-Output "done"
	Write-Output ""


	Write-Output "Request Certificate _____________________________________________________________"
	New-PACertificate $Domains -Force:$Force
	$order = Get-PAOrder -Refresh
	if ($order.status -ne "valid") {
		$order | Format-List
		throw ("order wasn't valid, but should have been at this point in the script")
	}
	if (! (Get-PACertificate)) {
		throw ("certificate didn't exist, which shouldn't be able to happen given the above validations that already ran")
	}
	Write-Output ""
}

function Set-Server {
	$Server = Get-PAServer
	if (! $Server) {
		if ($Staging) {
			Write-Output "Select staging server"
			Set-PAServer LE_STAGE
		} else {
			Write-Output "Select production server"
			Set-PAServer LE_PROD
		}
	} else {
		<# Make sure Staging matches Staging parameter #>
		if ($Server.location.Contains('staging')) {
			if ($Staging) {
				Write-Output "correct server already selected"
			} else {
				Write-Output "Switch from Staging to Production"
				Set-PAServer LE_PROD
			}
		} elseif ($Staging) {
			Write-Output "Switch from Production to Staging"
			Set-PAServer LE_STAGE
		} else {
			Write-Output "correct server already selected"
		}
	}
}

function Schedule-Task {
	if ($Time.Date -eq $Start.Date) {
		# Date contained in Time parameter was today, so add IntervalDays
		$Time = $Time.AddDays($IntervalDays)
	}
	if ($PSCmdlet.ShouldProcess(
		"Schedule a task to renew the certificate every $IntervalDays days starting ${Time}", #NOTE: shown with -WhatIf parameter
		"NOTE: If the fmsadmin.exe command cannot run without having to type the username/password when this script is run, the task will fail.",
		"Schedule a task to renew the certificate every $IntervalDays days starting ${Time}?"
	)) {
		$StagingParameterAsText = if ($Staging) {"-Staging"}
		$ForceParameterAsText = if ($Force) {"-Force"}
		$Action = New-ScheduledTaskAction `
			-Execute powershell.exe `
			-Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ""& '$PSCommandPath' -Renew $StagingParameterAsText $ForceParameterAsText -Confirm:0"""

		$Trigger = New-ScheduledTaskTrigger `
			-Daily `
			-DaysInterval $IntervalDays `
			-At $Time

		$Settings = New-ScheduledTaskSettingsSet `
			-DontStopIfGoingOnBatteries `
			-ExecutionTimeLimit 00:30

		$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings `
			-Description "Get an SSL certificate from Let's Encrypt and install it on FileMaker Server."

		$TaskName = "GetSSL"

		try {
			Write-Output ("You will now be asked for your Windows password, you should trust this script before entering it. You can audit this section of code by reviewing line #{0} of {1}." -f (Get-ScriptLineNumber), (Split-Path $PSCommandPath -Leaf))
			$credentials = Get-Credential `
				-UserName $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
				-Message "Windows user to run the task"

			Register-ScheduledTask -TaskName $TaskName -InputObject $Task -Force `
				-User $credentials.UserName `
				-Password $credentials.GetNetworkCredential().Password
		}
		finally { $credentials = $null }
	}
}

function Test-Administrator	{
# NOTE: must be admin to create challenge file in hosted directory
	$user = [Security.Principal.WindowsIdentity]::GetCurrent()
	(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-IsInteractiveShell {
<#
	.SYNOPSIS
		Returns boolean determining if prompt was run noninteractive.
	.DESCRIPTION
		First, we check `[Environment]::UserInteractive` to determine if we're if the shell if running 
		interactively. An example of not running interactively would be if the shell is running as a service.
		If we are running interactively, we check the Command Line Arguments to see if the `-NonInteractive` 
		switch was used; or an abbreviation of the switch.
	.LINK
		https://github.com/UNT-CAS/Test-IsNonInteractiveShell
		(function was modified from this version before adding to GetSSL.ps1)
#>
	return ([Environment]::UserInteractive -and (-not ([Environment]::GetCommandLineArgs() | ?{ $_ -like '-NonI*' })))
}

function Test-FMSAccess {
<#
	.SYNOPSIS
		Determine if user has to enter username and password to perform fmsadmin.exe
		Alternatively, if $userAndPassParamString is set, will test if those credentials are valid.
		(This is handled by the Invoke-FMSAdmin function)

	.OUTPUTS
		Boolean $true if user can access fmsadmin.exe
#>
	try {
		Invoke-FMSAdmin list, files -Timeout 5 | Out-Null
		return $true
	}
	catch {
		# If process exceeded timeout, assume it asked user for credentials, but since the window was hidden, user
		# could not see/enter them, therefor they don't have access to fmsadmin.exe without providing credentials.
		return $false
	}
}

#########################################################################################################################

Try {
	$Start = Get-Date # Save start date/time so it can be accessed repeatedly throughout the script

	<# Options that are unlikely to need to be changed #>
	[string] $FMSPath = 'C:\Program Files\FileMaker\FileMaker Server\'
	[int]    $LogsToKeep = 50
	[switch] $Logging = -not $host.name.contains('ISE')
	[string] $LogDirectory = Join-Path $FMSPath ('Data\Documents\' + (Split-Path $PSCommandPath -Leaf))
	[string] $fmsadmin = Join-Path $FMSPath 'Database Server\fmsadmin.exe' | Convert-Path
	$externalAuth = '' # declare as script-level variable
	$userAndPassParamString = '' # declare as script-level variable (set user/pass here if you want to hard-code it in your script)

	if (-not (Test-Administrator)) {
		throw 'This script must be run as Administrator'
	}
	
	if ($Logging) {
		If ( -not (Test-Path $LogDirectory) ) { New-Item -ItemType directory -Path $LogDirectory | Out-Null}
		$LogFilePath = Join-Path $LogDirectory "\powershell $($Start.ToString("yyyy-MM-dd_HHmmss")).log"
		Start-Transcript -Append -Path $LogFilePath
	}

	Write-Output $Start.ToString("F") # add nicely formatted date to logs
	Write-Output ""

	switch ($PSCmdlet.ParameterSetName) {
		'Setup' {
			if (-not(Get-Module -Listavailable -Name Posh-ACME*)) {
				Write-Output "Posh-ACME module not found, Installing Dependencies..."
				Install-Dependencies
				Write-Output "done"
			}
			Write-Output "Setup..."
			Set-Server
			# NOTE: $Setup may or may not be set since passing -Domains and -Emails parameter will activate Setup mode even without the -Setup flag
			if (! $Setup) { [switch] $Setup = $True }
		}
		
		'Renew' {
			Write-Output "Renew..."
			Set-Server
			
			# get Emails from Get-PAAccount
			$account = Get-PAAccount
			if (! $account) {
				throw "No ACME account configured. Run Setup first."
			}
			$Emails = ($account.contact).Replace('mailto:','')
			
			# get Domains from Get-PAOrder
			$order = Get-PAOrder -Refresh
			if (! $order) {
				throw "No previously configured order found. Run Setup first."
			}
			$Domains = @($order.MainDomain) + $order.SANs
		}
		
		{$_ -in 'Setup','Renew'} {
			Write-Output "  domains:      $($Domains -join ', ')"
			Write-Output "  emails:       $($Emails -join ', ')"
			Write-Output "  Staging:      $Staging"
			Write-Output "  Force:        $Force"
			Write-Output ""

			if ($Staging -and $Force) {
				<# either the first message is shown, or both the second AND third #>
				$messages = @(
					<# verboseDescription: Textual description of the action to be performed. This is what will be displayed to the user for ActionPreference.Continue. (-WhatIf parameter will show this) #>
					"Replace FileMaker Server Certificate with one from Let's Encrypt Staging server, then restart FileMaker Server service.",

					<# verboseWarning: Textual query of whether the action should be performed, usually in the form of a question. This is what will be displayed to the user for ActionPreference.Inquire. #>
					"If you proceed, and this script is successful, FileMaker Server service will be restarted and ALL USERS DISCONNECTED.",

					<# caption: Caption of the window which may be displayed if the user is prompted whether or not to perform the action. caption may be displayed by some hosts, but not all.#>
					"Replace with Staging Certificate?"
				)
			} elseif ($Staging) {
				<# either the first message is shown, or both the second AND third #>
				$messages = @(
					"Replace FileMaker Server Certificate with one from Let's Encrypt Staging server, will NOT restart FileMaker Server service, because this is just for testing/setup.",
					"Will NOT restart FileMaker Server service, because this is just for testing/setup, right?",
					"Replace with Staging Certificate?"
				)
			} else {
				$messages = @(
					"Replace FileMaker Server Certificate with one from Let's Encrypt, then restart FileMaker Server service.",
					"If you proceed, and this script is successful, FileMaker Server service will be restarted and ALL USERS DISCONNECTED.",
					"Replace Certificate?"
				)
			}

			if ($PSCmdlet.ShouldProcess($messages[0], $messages[1], $messages[2])) {
				Write-Output ""
				New-Cert
				Install-Cert

				if (Test-IsInteractiveShell) {
					# just call the script again to schedule a task; it will ask user if they want to proceed
					& $PSCommandPath -ScheduleTask -Staging:$Staging -Force:$Force
				}
			}

			break
		}

		'InstallCertificate' {
			Write-Output "InstallCertificate..."
			Write-Output "  Staging:      $Staging"
			Write-Output ""

			if ($Staging -and $Force) {
				$messages = @(
					"Replace FileMaker Server Certificate with stored Staging certificate, then restart FileMaker Server service.",
					"If you proceed, and this script is successful, FileMaker Server service will be restarted and ALL USERS DISCONNECTED.",
					"Replace with Staging Certificate?"
				)
			} elseif ($Staging) {
				$messages = @(
					"Replace FileMaker Server Certificate with stored Staging certificate, will NOT restart FileMaker Server service, because this is just for testing/setup.",
					"Will NOT restart FileMaker Server service, because this is just for testing/setup, right?",
					"Replace with Staging Certificate?"
				)
			} else {
				$messages = @(
					"Replace FileMaker Server Certificate stored certificate, then restart FileMaker Server service.",
					"If you proceed, and this script is successful, FileMaker Server service will be restarted and ALL USERS DISCONNECTED.",
					"Replace Certificate?"
				)
			}

			if ($PSCmdlet.ShouldProcess($messages[0], $messages[1], $messages[2])) {
				Write-Output ""
				Set-Server
				Install-Cert
			}

			break
		}

		'ScheduleTask' {
			Write-Output "ScheduleTask..."
			Write-Output "  Staging:      $Staging"
			Write-Output "  Force:        $Force"
			Write-Output ""
			Schedule-Task
			
			if (-not(Get-StoredCredential -Target "GetSSL Send Email")) {
				if ($PSCmdlet.ShouldProcess(
					"Configure this script to email logs?",
					"Configure this script to email logs?",
					"Configure email?"
				)) {
					& $PSCommandPath -ConfigureEmail
				} else {
					Write-Output "Can do this later with this command:"
					Write-Output "  .'$PSCommandPath' -ConfigureEmail"
				}
			}

			break
		}

		'ConfigureEmail' {
			Write-Output "ConfigureEmail..."
			Write-Output ""

			$from = Read-Host -Prompt ("Send from address")

			Write-Output "Common Server URLs:"
			Write-Output "  Gmail               smtp.gmail.com"
			Write-Output "  Outlook.com         smtp.live.com"
			Write-Output "  Office365           smtp.office365.com"
			Write-Output "  Yahoo               smtp.mail.yahoo.com"
			Write-Output "  Hotmail             smtp.live.com"
			$server = Read-Host -Prompt ("SMTP Server URL")

			Write-Output "Common Ports:"
			Write-Output "  Gmail               587"
			Write-Output "  Outlook.com         587"
			Write-Output "  Office365           587"
			Write-Output "  Yahoo               465"
			Write-Output "  Hotmail             465"
			do {
				$port = Read-Host -Prompt ("SMTP Port")
				try { $port = [int]$port }
				catch {
					Write-Output "port must be an integer"
					$port = $null
				}
			}
			until ($port)

			Write-Output "Common useSSL setting:"
			Write-Output "  Gmail               y"
			Write-Output "  Outlook.com         y"
			Write-Output "  Office365           y"
			Write-Output "  Yahoo               y (I'm assuming)"
			Write-Output "  Hotmail             y"
			do {
				$useSSL = Read-Host -Prompt ("SMTP useSSL [y or n]")
				if ($useSSL.ToLower() -eq 'y')     { $useSSL = $True }
				elseif ($useSSL.ToLower() -eq 'n') { $useSSL = $False }
				else                               { $useSSL = $null }
			}
			until ($useSSL -is [Boolean])

			$smtpInfo = @{from=$from; server=$server; port=$port; useSSL=$useSSL}
			$smtpInfo | Format-Table
			$smtpInfoJSON = ($smtpInfo | ConvertTo-Json -Compress)

			Get-Credential -Message "GetSSL Send Email" | New-StoredCredential -Target "GetSSL Send Email" -Persist LocalMachine -Comment $smtpInfoJSON | Out-Null
			
			Send-Email -Subject "GetSSL setup test" `
				-Body "If you get this email, then GetSSL has been configured to send logs via email when it's run via scheduled task."

			break
		}

		Default {
			# InstallDependencies by default
			Write-Output "Installing Dependencies..."
			Install-Dependencies
			Write-Output "done"

			if ($PSCmdlet.ShouldProcess(
				"Setup and install a certificate now?",
				"Setup and install a certificate now?",
				"Setup?"
			)) {
				& $PSCommandPath -Setup -Staging:$Staging -Force:$Force
			} else {
				Write-Output "When ready, you can setup and install a certificate:"
				Write-Output "  .'$PSCommandPath' -Setup"
			}

		}
	}
}

Catch {
	<# Make sure the error is logged in the transcript #>
	$_ | Out-String
	Write-Output "Stack Trace:" $_.ScriptStackTrace
	<# Throw it again so it sets an exit code #>
	throw
}

Finally {
	if ($mustStartServer) {
		Write-Output "mustStartServer was still true in Finally block, so try to start it..."
		if ((Get-Service "FileMaker Server").Status  -ne "Running") {
			Write-Output "FileMaker Server service was not running, it will be started now"
			Start-Service "FileMaker Server"
			Start-Sleep 2 # give the service a few seconds to start before testing if fmserver is running
		}
		$retries = 4
		$timeout = 90
		while ($true) {
			$retries--
			try {
				Write-Output ("with timeout of $timeout seconds, starting at {0}..." -f (Get-Date).ToLongTimeString())
				Invoke-FMSAdmin start, server -Timeout $timeout
				break
			}
			catch [System.TimeoutException] {
				if ($retries -gt 0) {
					Write-Output "  timed out, $retries attempt(s) left before aborting"
					$timeout *= 2
				} else {
					Write-Output "Sorry, still couldn't start server"
					break
				}
			}
			catch [System.ApplicationException] {
				# NOTE: Error: 10007 (Requested object does not exist) occurs when service is stopped
				if ($_.Exception.Message.StartsWith("fmsadmin") -and ($_.Exception.Data.ExitCode) -eq 10006) {
					Write-Output "(If server is set to start automatically, error 10006 is expected)"
				} else {
					Write-Output "Sorry, still couldn't start server"
				}
				break
			}
		}
		if ($WPEWasRunning) {
			try {Invoke-FMSAdmin start, wpe} catch{}
		}
		if ($FilesWereOpen) {
			try {Invoke-FMSAdmin open -Timeout 60}
			catch {
				# blindly try again, giving it more time
				try {Invoke-FMSAdmin open -Timeout 180} catch{}
			}
		}
	}

	<# Overwrite sensitive variables to get them out of memory #>
	$fmsCredential = $username = $password = $userAndPassParamString = $null

	if ($Logging) {
		Try { Write-Output ""; (Get-Help -Full $PSCommandPath).alertSet.alert.Text }
		Catch { Write-Output "failed to extract script version from header comment"; $_ }

		Try {
			Write-Output "`r`nmodule versions installed:"
			(Get-Module -Listavailable -Name Posh-ACME.net46, Posh-ACME, CredentialManager -ErrorAction Ignore |
				Select-Object Name, Version | Format-Table -HideTableHeaders | Out-String ).Trim()
			Write-Output "`r`nmodule versions used:"
			(Get-InstalledModule -Name Posh-ACME.net46, Posh-ACME, CredentialManager -ErrorAction Ignore |
				Select-Object Name, Version | Format-Table -HideTableHeaders | Out-String ).Trim()
		}
		Catch { Write-Output "failed to get Posh-ACME module version"; $_ }

		Write-Output ""
		Write-Output (Get-Date).ToString("F") # add nicely formatted date to log
		Write-Output "Delete old Log files, if necessary."
		Get-ChildItem $LogDirectory -Filter *.log | Sort CreationTime -Descending | Select-Object -Skip $LogsToKeep | Remove-Item -Force
		Try {Stop-Transcript | Out-Null} Catch [System.InvalidOperationException] {}

		if (-not (Test-IsInteractiveShell)) {
			Send-Email -Subject GetSSL $Domains -Body (Get-Content $LogFilePath -Raw)
		}
	}
}
