<#
.SYNOPSIS
	Get an SSL certificate from Let's Encrypt and install it on FileMaker Server.

.PARAMETER Domains
	Array of domain(s) for which you would like an SSL Certificate.
	Let's Encrypt will peform separate validation for each of the domains,
	so be sure that your server is reachable at all of them before
	attempting to get a certificate. 100 domains is the max.

.PARAMETER Email
	Contact email address to your real email address so that Let's Encrypt
	can contact you if there are any problems.

.PARAMETER FMSPath
	Path to your FileMaker Server directory, ending in a backslash. Only
	necessary if installed in a non-default location.

.PARAMETER Staging
	Use Let's Encrypt Staging server and don't restart FileMaker Server service.
	Use this option for testing/setup, but beware that the certificate will be
	imported, so you would either need to restore the old certificate or
	call this script again without this parameter to install a production
	certificate.

.PARAMETER Logging
	Enable or disable logging. Default is to enable if not called from
	PowerShell Integrated Scripting Environment (ISE).

.PARAMETER LogDirectory
	Folder to put logs. Default is a folder named the same as this script in
	a Documents directory that is a sibling to this scripts parent directory.
	In other words: Documents directory when this script is in FMS Scripts
	directory.

.PARAMETER LogsToKeep
	Number of log files to keep in LogDirectory. Oldest will be deleted if
	there are more than this number.

.PARAMETER ScheduleTask
	Schedule a task via Windows Task Scheduler to renew the certificate
	automatically via Windows Task Scheduler.

.PARAMETER IntervalDays
	When scheduling a task, specify an interval to repeat on. Default is 63
	days because:
		- Let's Encrypt's recommendation is to renew when a certificate has a
		  third of it's total lifetime left.
		- if interval is divisible by 7, then it will always occur on the same
		  day of the week

.PARAMETER Time
	When scheduling a task, specify a time of day to run it. Can optionally
	specify the exact date/time of the first schedule.

.NOTES
	File Name:   GetSSL.ps1
	Author:      David Nahodyl contact@bluefeathergroup.com, modified by Daniel Smith dan@filemaker.consulting
	Created:     2016-10-08
	Revised:     2018-05-22
	Version:     0.9-DS

.LINK
	https://github.com/dansmith65/FileMaker-LetsEncrypt-Win

.LINK
	http://bluefeathergroup.com/blog/how-to-use-lets-encrypt-ssl-certificates-with-filemaker-server/

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
	.\GetSSL.ps1 -Domain test.com -Email user@test.com

	Or full parameter names.

.EXAMPLE
	.\GetSSL.ps1 test.com user@test.com -FMSPath "X:\FileMaker Server\"

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


[cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
Param(
	[Parameter(Mandatory=$True,Position=1)]
	[Alias('d')]
	[string[]] $Domains,

	[Parameter(Mandatory=$True,Position=2)]
	[Alias('e')]
	[string] $Email,

	[Parameter(Position=3)]
	[Alias('p')]
	[string] $FMSPath = 'C:\Program Files\FileMaker\FileMaker Server\',

	[switch] $Staging=$False,

	[switch] $Logging = -not $host.name.contains('ISE') ,

	[int] $LogsToKeep = 50 ,

	[string] $LogDirectory = "$(Split-Path $(Split-Path (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Path))\Documents\$($MyInvocation.MyCommand.Name)",

	[Parameter(ParameterSetName='ScheduleTask')]
	[Alias('s')]
	[switch] $ScheduleTask=$False,

	[Parameter(ParameterSetName='ScheduleTask')]
	[Alias('i')]
	[string] $IntervalDays=63,

	[Parameter(ParameterSetName='ScheduleTask')]
	[Alias('t')]
	[DateTime] $Time="4:00am"
)


<# Exit immediately on error #>
$ErrorActionPreference = "Stop"

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

function Confirm-FMSAccess {
<#
	.SYNOPSIS
		Determine if user has to enter username and password to perform fmsadmin.exe

	.OUTPUTS
		Boolean $true if user can access fmsadmin.exe
#>
	Param(
		[Parameter(Position=1)]
		[Alias('u')]
		[string]$username = $null,

		[Parameter(Position=2)]
		[Alias('p')]
		[string]$password = $null,

		[string]$fmsadmin = 'C:\Program Files\FileMaker\FileMaker Server\Database Server\fmsadmin.exe',

		[int]$timout = 3
	)

	$userAndPassParamString = $null
	if ($username -and $password) {
		$userAndPassParamString = "-u $username -p $password"
	}
	$Process = Start-Process -FilePath $fmsadmin -ArgumentList "list files $userAndPassParamString" -PassThru -WindowStyle Hidden
	try {
		Wait-Process -InputObject $Process -Timeout $timout -ErrorAction Stop
		if ($Process.ExitCode) {
			if ($Process.ExitCode -eq 10502) {
				Write-Debug "Error code 10502 likely means the server was not started"
			}
			return $false
		}
		return $true
	}
	catch {
		# If process exceeded timeout, assume it asked user for credentials, but since the window was hidden, user
		# could not see/enter them, therefor they don't have access to fmsadmin.exe without providing credentials.
		$Process | Stop-Process -Force
		return $false
	}
}

function Test-Administrator	{
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

Try {
	<# Save start date/time so it can be accessed repeatedly throughout the script #>
	$Start = Get-Date

	if ( $Logging ) {
		If ( -not (Test-Path $LogDirectory) ) { New-Item -ItemType directory -Path $LogDirectory }
		$LogFilePath = Join-Path $LogDirectory "\powershell $($Start.ToString("yyyy-MM-dd_HHmmss")).log"
		Start-Transcript -Append -Path $LogFilePath
		Write-Output ""
	}

	$fmsadmin = Join-Path $FMSPath 'Database Server\fmsadmin.exe' | Convert-Path

	<# Display user input #>
	Write-Output $Start.ToString("F")
	Write-Output ""
	Write-Output('  domains:      '+($Domains -join ', '))
	Write-Output "  email:        $Email"
	Write-Output "  FMSPath:      $FMSPath"
	Write-Output "  Staging:      $Staging"
	Write-Output "  Logging:      $Logging"
	if ( $Logging ) {
	Write-Output "  LogDirectory: $LogDirectory"
	Write-Output "  LogsToKeep:   $LogsToKeep"
	}
	Write-Output ""


	<# validate FMSPath #>
	if (-not(Test-Path $fmsadmin)) {
		throw "fmsadmin could not be found at: '$fmsadmin', please check the FMSPath parameter: '$FMSPath'"
	}

	<# Check to make sure we're running as admin #>
	if (-not (Test-Administrator)) {
		throw 'This script must be run as Administrator'
	}

	<# Server must be started to import a certificate or confirm access #>
	if (-not(Get-Process fmserver -ErrorAction:Ignore)) {
		Write-Output "FileMaker Server process was not running, it will be started now"
		& $fmsadmin start server
		if (! $?) { throw ("failed to start server, error code " + $LASTEXITCODE) }
		Start-Sleep -Seconds 1
		if (-not(Get-Process fmserver -ErrorAction:Ignore)) {
			throw ("server process still not running after starting it; check FileMaker logs to see what's wrong")
		}
		<# Sometimes external authentication fails right after starting server; trigger that failure here #>
		Confirm-FMSAccess -Timout 1
	}

	Write-Output "Attempt to load credentials from Credential Manager"
	$userAndPassParamString = $null
	if (Get-Module -Listavailable -Name CredentialManager) {
		Import-Module CredentialManager
	} else {
		Write-Output "Install CredentialManager"
		Install-Module -Name CredentialManager -AllowClobber -Confirm:$false -Force
	}
	$fmsCredential = Get-StoredCredential -Target "GetSSL FileMaker Server Admin Console"
	if ($fmsCredential) {
		$username = $fmsCredential.UserName
		$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($fmsCredential.Password)
		$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
		$fmsCredential = $bstr = $null
		if ($username -and $password) {
			$userAndPassParamString = "-u $username -p $password"
			Write-Output "found em!"
		} else {
			$username = $password = $null
		}
	} else {
		Write-Output "no luck"
	}
	Write-Output ""

	Write-Output "Confirming access to fmsadmin.exe:"
	$FMAccessConfirmed = Confirm-FMSAccess $username $password -Timout 1
	if (-not ($FMAccessConfirmed)) {
		<# Sometimes fmsadmin asks for a password even if it's configured properly to use external
		   authentication, check again to be sure it's for real.
		   https://community.filemaker.com/message/803496 #>
		$FMAccessConfirmed = Confirm-FMSAccess $username $password
	}
	if (-not ($FMAccessConfirmed)) {
		if (Test-IsInteractiveShell) {
			Write-Output "no access!"
			Write-Output "A window will open where you can securely enter your fmsadmin login. Sometimes it takes a moment to open."
			while (-not $FMAccessConfirmed) {
				$fmsCredential = Get-Credential -Message "FileMaker Server Admin Console Sign In"
				if ($fmsCredential) {
					$username = $fmsCredential.UserName
					$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($fmsCredential.Password)
					$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
					$fmsCredential = $bstr = $null
					$FMAccessConfirmed = Confirm-FMSAccess $username $password
					if (-not $FMAccessConfirmed) {
						$username = $password = $null
						Write-Output "That account didn't work, please try again."
					}
				} else {
					Write-Output "no access!"
					if (-not ($PSCmdlet.ShouldProcess(
							"Permissions not setup to allow performing fmsadmin.exe without entering your username and password multiple times.",
							"Permissions not setup to allow performing fmsadmin.exe without entering your username and password multiple times.",
							"Continue?"
						)))
					{
						exit
					}
					Break
				}
			}
			
			if ($FMAccessConfirmed) {
				$userAndPassParamString = "-u $username -p $password"
				New-StoredCredential -Target "GetSSL FileMaker Server Admin Console" -Persist LocalMachine -UserName $username -Password $password | Out-Null
			}
			
		} else {
			throw ( "no access! Must be able to perform fmsadmin without entering user/pass when this script is not run interactively" )
		}
	} else {
		Write-Output "confirmed"
	}
	Write-Output ""


	if ($ScheduleTask) {
		if ($Time.Date -eq $Start.Date) {
			#Date contained in Time parameter was today, so add IntervalDays
			$Time = $Time.AddDays($IntervalDays)
		}
		if ($PSCmdlet.ShouldProcess(
			"Schedule a task to renew the certificate every $IntervalDays days starting ${Time}", #NOTE: shown with -WhatIf parameter
			"NOTE: If the fmsadmin.exe command cannot run without having to type the username/password when this script is run, the task will fail.",
			"Schedule a task to renew the certificate every $IntervalDays days starting ${Time}?"
		)) {
			$StagingParameterAsText = if ($Staging) {"-Staging"}
			$Action = New-ScheduledTaskAction `
				-Execute powershell.exe `
				-Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"& '$($MyInvocation.MyCommand.Path)' -Domains $Domains -Email $Email -FMSPath '$FMSPath' $StagingParameterAsText -Confirm:0`""

			$Trigger = New-ScheduledTaskTrigger `
				-Daily `
				-DaysInterval $IntervalDays `
				-At $Time

			$Settings = New-ScheduledTaskSettingsSet `
				-AllowStartIfOnBatteries `
				-DontStopIfGoingOnBatteries `
				-ExecutionTimeLimit 00:10 `
				-StartWhenAvailable

			$Principal = New-ScheduledTaskPrincipal `
				-UserId $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
				-LogonType S4U `
				-RunLevel Highest

			$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal `
				-Description "Get an SSL certificate from Let's Encrypt and install it on FileMaker Server."

			$TaskName = "GetSSL $Domains"

			Register-ScheduledTask -TaskName $TaskName -InputObject $Task -Force
		}
		exit
	}

	if (!($Staging)) {
		<# either the first message is show, or both the second AND third #>
		$messages = @(
			<# verboseDescription: Textual description of the action to be performed. This is what will be displayed to the user for ActionPreference.Continue. (-WhatIf parameter will show this) #>
			"Replace FileMaker Server Certificate with one from Let's Encrypt, then restart FileMaker Server service.",

			<# verboseWarning: Textual query of whether the action should be performed, usually in the form of a question. This is what will be displayed to the user for ActionPreference.Inquire. #>
			"If you proceed, and this script is successful, FileMaker Server service will be restarted and ALL USERS DISCONNECTED.",

			<# caption: Caption of the window which may be displayed if the user is prompted whether or not to perform the action. caption may be displayed by some hosts, but not all.#>
			"Replace FileMaker Server Certificate with one from Let's Encrypt?"
		)
	} else {
		$messages = @(
			"Replace FileMaker Server Certificate with one from Let's Encrypt Staging server, will NOT restart FileMaker Server service, because this is just for testing/setup.",

			"Will NOT restart FileMaker Server service, because this is just for testing/setup, right?",

			"Replace FileMaker Server Certificate with one from Let's Encrypt Staging server?"
		)
	}

	if ($PSCmdlet.ShouldProcess($messages[0], $messages[1], $messages[2])) {
		$domainAliases = @();
		foreach ($domain in $Domains) {
			if ($domain -Match ",| ") {
				throw "Domain cannot contain a comma or parameter; perhaps two domains were passed as a single string? Try removing quotes from the domains."
			}
			$domainAliases += "$domain"+[guid]::NewGuid().ToString()
		}


		if (Get-Module -Listavailable -Name ACMESharp) {
			Write-Output "Import ACMESharp Module"
			Import-Module ACMESharp
		} else {
			Write-Output "Install ACMESharp"
			Install-Module -Name ACMESharp, ACMESharp.Providers.IIS -AllowClobber -Confirm:$false -Force
			Enable-ACMEExtensionModule -ModuleName ACMESharp.Providers.IIS
		}
		Write-Output ""

		<# Initialize the vault to either Live or Staging#>
		$Vault = Get-ACMEVault
		if (!($Vault)) {
			Write-Output "Initialize-ACMEVault"
			if ($Staging) {
				Initialize-ACMEVault -BaseService LetsEncrypt-STAGING
			} else {
				Initialize-ACMEVault
			}
		} else {
			<# Make sure vault matches Staging parameter #>
			if ($Vault.BaseUri.Contains('staging')) {
				if (!($Staging)) {
					Write-Output "Switch Vault from Staging to Production"
					Initialize-ACMEVault -Force
				}
			} elseif ($Staging) {
				Write-Output "Switch Vault from Production to Staging"
				Initialize-ACMEVault -BaseService LetsEncrypt-STAGING -Force
			}
		}


		Write-Output "Register contact info with LE"
		New-ACMERegistration -Contacts mailto:$Email -AcceptTos


		<# ACMESharp creates a web.config that doesn't work so let's SkipLocalWebConfig and make our own
			(it seems to think text/json is required) #>
		$webConfigPath = Join-Path $FMSPath 'HTTPServer\conf\.well-known\acme-challenge\web.config'

		<# Create directory the file goes in #>
		if (-not (Test-Path (Split-Path -Path $webConfigPath -Parent))) {
			Write-Output "Create acme-challenge directory"
			New-Item -Path (Split-Path -Path $webConfigPath -Parent) -ItemType Directory
		}

		Write-Output "Create web.config file"
		'<configuration>
			<system.webServer>
				<staticContent>
					<mimeMap fileExtension="." mimeType="text/plain" />
				</staticContent>
			</system.webServer>
		</configuration>' | Out-File -FilePath ($webConfigPath)
		Write-Output "done"
		Write-Output ""


		<# Loop through the array of domains and validate each one with LE #>
		for ( $i=0; $i -lt $Domains.length; $i++ ) {
			<# Create a UUID alias to use for our domain request #>
			$domain = $Domains[$i]
			$domainAlias = $domainAliases[$i]
			Write-Output "Performing challenge for $domain with alias $domainAlias";

			<#Create an entry for us to use with these requests using the alias we just generated #>
			New-ACMEIdentifier -Dns $domain -Alias $domainAlias;

			<# Use ACMESharp to automatically create the correct files to use for validation with LE #>
			$response = Complete-ACMEChallenge $domainAlias -ChallengeType http-01 -Handler iis -HandlerParameters @{ WebSiteRef = 'FMWebSite'; SkipLocalWebConfig = $true } -Force

			<# Sample Response
			== Manual Challenge Handler - HTTP ==
			  * Handle Time: [1/12/2016 1:16:34 PM]
			  * Challenge Token: [2yRd04TwqiZTh6TWLZ1azL15QIOGaiRmx8MjAoA5QH0]
			To complete this Challenge please create a new file
			under the server that is responding to the hostname
			and path given with the following characteristics:
			  * HTTP URL: [http://myserver.example.com/.well-known/acme-challenge/2yRd04TwqiZTh6TWLZ1azL15QIOGaiRmx8MjAoA5QH0]
			  * File Path: [.well-known/acme-challenge/2yRd04TwqiZTh6TWLZ1azL15QIOGaiRmx8MjAoA5QH0]
			  * File Content: [2yRd04TwqiZTh6TWLZ1azL15QIOGaiRmx8MjAoA5QH0.H3URk7qFUvhyYzqJySfc9eM25RTDN7bN4pwil37Rgms]
			  * MIME Type: [text/plain]------------------------------------
			#>

			<# Let them know it's ready #>
			Write-Output "Submit-ACMEChallenge"
			Submit-ACMEChallenge $domainAlias -ChallengeType http-01 -Force;

			Write-Output "Update-ACMEIdentifier: Wait for LE to validate settings"
			$timeout = New-TimeSpan -Minutes 1
			$sw = [diagnostics.stopwatch]::StartNew()
			do {
				<# I tested with 1ms sleep and it was valid on the first iteration,
				   but to be curtious to LE's server's, I set it to sleep for 1 second #>
				Start-Sleep -Seconds 1
				$response = (Update-ACMEIdentifier $domainAlias -ChallengeType http-01)
				$status = ($response.Challenges | Where-Object {$_.Type -eq "http-01"}).Status
				if ($sw.elapsed -gt $timeout) {
					$response
					$response.Challenges
					$status
					throw ("timed out")
				}
				Write-Host -NoNewline "."
			}
			until ($status -ne "pending")
			if ($status -ne "valid") {
				throw ("unexpected status value: $status")
			}
			Write-Output "done"
			Write-Output ""
		}



		$certAlias = 'cert-'+[guid]::NewGuid().ToString()

		<# Ready to get the certificate #>
		Write-Output "New-ACMECertificate"
		New-ACMECertificate $domainAliases[0] -Generate -AlternativeIdentifierRefs $domainAliases -Alias $certAlias

		Write-Output "Submit-ACMECertificate"
		Submit-ACMECertificate $certAlias

		Write-Output "Update-ACMECertificate: Wait for LE to create the certificate"
		$timeout = New-TimeSpan -Minutes 1
		$sw = [diagnostics.stopwatch]::StartNew()
		do {
			Start-Sleep -Seconds 1
			$response = (Update-ACMECertificate $certAlias)
			$issuerSerialNumber = $response.IssuerSerialNumber
			if ($sw.elapsed -gt $timeout) {
				$response
				$issuerSerialNumber
				throw ("timed out")
			}
			Write-Host -NoNewline "."
		}
		until ($issuerSerialNumber)
		Write-Output "done"
		Write-Output ""


		Write-Output "Export the private key"
		$keyPath = Join-Path $FMSPath 'CStore\serverKey.pem'
		if (Test-Path $keyPath) {
			Backup-File $keyPath
			Remove-Item $keyPath
		}
		Get-ACMECertificate $certAlias -ExportKeyPEM $keyPath

		Write-Output "Export the certificate"
		$certPath = Join-Path $FMSPath 'CStore\crt.pem'
		if (Test-Path $certPath) {
			Backup-File $certPath
			Remove-Item $certPath
		}
		Get-ACMECertificate $certAlias -ExportCertificatePEM $certPath

		Write-Output "Export the Intermediary"
		$intermPath = Join-Path $FMSPath 'CStore\interm.pem'
		if (Test-Path $intermPath) {
			Backup-File $intermPath
			Remove-Item $intermPath
		}
		Get-ACMECertificate $certAlias -ExportIssuerPEM $intermPath

		$serverCustomPath = Join-Path $FMSPath 'CStore\serverCustom.pem'
		if (Test-Path $intermPath) {
			Backup-File $serverCustomPath
			Write-Output ""
		}

		Write-Output "Import certificate via fmsadmin:"
		<# NOTE: use this method of calling fmsadmin whenever it's possible for it to ask user for
		   input. Otherwise, just call it directly. Note that this call has two paths which must be
		   quoted, so the syntax for escaping quotes is more complicated than if there is only one
		   path, like when stopping the server
		   https://community.filemaker.com/thread/191306
		#>
		cmd /c "`"$fmsadmin`" certificate import `"$certPath`" -y $userAndPassParamString"
		if (! $?) { throw ("fmsadmin certificate import error code " + $LASTEXITCODE) }
		Write-Output "done"
		Write-Output ""

		Write-Output "Append the intermediary certificate:"
		<# to support older FMS before 15 #>
		Add-Content $serverCustomPath (Get-Content $intermPath)
		Write-Output "done"
		Write-Output ""

		Write-Output "Stop FileMaker Server:"
		if ($Staging) {
			Write-Output "skipped because -Staging parameter was provided"
		} else {
			$WPEWasRunning = Get-Process fmscwpc -ErrorAction:Ignore
			if ($FMAccessConfirmed) {
				<# Only run this code if user will not be prompted for user/pass since this method
				   of calling fmsadmin does not allow them to enter their user/pass #>
				$FilesWereOpen = & $fmsadmin list files $userAndPassParamString
			}
			cmd /c $fmsadmin stop server -y $userAndPassParamString
			if (! $?) { throw ("error code " + $LASTEXITCODE) }
		}
		Write-Output "done"
		Write-Output ""

		Write-Output "Restart the FMS service:"
		if ($Staging) {
			Write-Output "skipped because -Staging parameter was provided"
		} else {
			Restart-Service "FileMaker Server"
		}
		Write-Output "done"
		Write-Output ""

		<# Just in case server isn't configured to start automatically #>
		Write-Output "Start FileMaker Server:"
		if ($Staging) {
			Write-Output "skipped because -Staging parameter was provided"
		} else {
			& $fmsadmin start server
			if ($LASTEXITCODE -eq 10006) {
				Write-Output "(If server is set to start automatically, error 10006 is expected)"
			}
			if ($WPEWasRunning -and -not(Get-Process fmscwpc -ErrorAction:Ignore)) {
				<# NOTE: this will only work as expected from 64 bit PowerShell since Get-Process only lists processes processes running the same bit depth as PowerShell #>
				Write-Output "start WPE because it was running before FMS was stopped, but isn't now:"
				& $fmsadmin start wpe
			}
			if ($FilesWereOpen) {
				<# Confirm FMAccess again, since it can asks for a password again after starting
				   server. Do it twice; first time will likely fail, second time should succeed.
				   https://community.filemaker.com/thread/191306 #>
				Confirm-FMSAccess $username $password | Out-Null
				if (Confirm-FMSAccess $username $password) {
					Write-Output "check if files are open"
					<# NOTE: If fmsadmin asks for a user/pass here, the user will not see the
					   request, will not be able to enter them, and the script will hang. #>
					if(-not(& cmd /c $fmsadmin list files $userAndPassParamString)) {
						Write-Output "open files because they were open before FMS was stopped, but aren't now:"
						cmd /c $fmsadmin open $userAndPassParamString
					}
				}
			} else {
				<# In this case, $FilesWereOpen wasn't set because that logic can't properly run
				   when the user has to enter their user/pass. So just assume files should be
				   opened and the user is at the console able to enter user/pass #>
				cmd /c $fmsadmin open $userAndPassParamString
			}
		}
		Write-Output "done"
		Write-Output ""
	}
}

Catch {
	<# Make sure the error is logged in the transcript #>
	$_ | Out-String
	<# Throw it again so it sets an exit code #>
	throw
}

Finally {
	<# Overwrite sensitive variables to get them out of memory #>
	$fmsCredential = $bstr = $username = $password = $userAndPassParamString = $null

	if ( $Logging ) {
		Write-Output ""
		Write-Output "Delete old Log files, if necessary."
		Get-ChildItem $LogDirectory -Filter *.log | Sort CreationTime -Descending | Select-Object -Skip $LogsToKeep | Remove-Item -Force
		Write-Output ""
		Try {
			Stop-Transcript | Out-Null
		}
		Catch [System.InvalidOperationException]{}

		if (-not (Test-IsInteractiveShell)) {
			if (Get-Module -Listavailable -Name CredentialManager) {
				Import-Module CredentialManager
				$credentials = Get-StoredCredential -Target "GetSSL Send Email"
				if ($credentials) {
					<# If CredentialManager is installed and user has stored credentials with the
					   required name, assume user has also configured the following section: #>
					Send-MailMessage -Subject "GetSSL Log $Domains" -Body (Get-Content $LogFilePath -Raw) -Encoding UTF8 -Credential $credentials -To $Email `
						-From user@email.com `
						-SmtpServer smtp.gmail.com `
						-Port 587 `
						-UseSsl
				}
			}
		}
	}
}
