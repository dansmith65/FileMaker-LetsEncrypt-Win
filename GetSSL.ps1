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

function Test-Administrator	{
	$user = [Security.Principal.WindowsIdentity]::GetCurrent()
	(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}


Try {
	<# Save start date/time so it can be accessed repeatedly throughout the script #>
	$Start = Get-Date

	if ( $Logging ) {
		If ( -not (Test-Path $LogDirectory) ) { New-Item -ItemType directory -Path $LogDirectory }
		Start-Transcript -Append -Path "$logDirectory\powershell $($Start.ToString("yyyy-MM-dd_HHmmss")).log"
		Write-Host
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

	<# Server must be started to import a certificate #>
	if (-not(Get-Process fmserver -ErrorAction:Ignore)) {
		Write-Output "FileMaker Server process was not running, it will be started now"
		& $fmsadmin start server
		if (! $?) { throw ("failed to start server, error code " + $LASTEXITCODE) }
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


		if (!(Get-Module -Listavailable -Name ACMESharp)) {
			Write-Output "Install ACMESharp"
			# NOTE: the -Confirm:$false option doesn't prevent ALL confirmations,
			# but it does prevent a few, which are most likely to only be
			# required on the first run 
			Install-Module -Name ACMESharp, ACMESharp.Providers.IIS -AllowClobber -Confirm:$false
			Enable-ACMEExtensionModule -ModuleName ACMESharp.Providers.IIS
		}
		Write-Output "Import ACMESharp Module"
		Import-Module ACMESharp

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

			<# Pause 10 seconds to wait for LE to validate our settings #>
			Start-Sleep -s 10

			<# Check the status #>
			Write-Output "Update-ACMEIdentifier"
			(Update-ACMEIdentifier $domainAlias -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}

			<# Good Response Sample
			ChallengePart          : ACMESharp.Messages.ChallengePart
			Challenge              : ACMESharp.ACME.HttpChallenge
			Type                   : http-01
			Uri                    : https://acme-v01.api.letsencrypt.org/acme/challenge/a7qPufJw0Wdk7-Icw6V3xDDlXj1Ag5CVr4aZRw2H27
									 A/323393389
			Token                  : CqAhe31xGDeaqzf01dPx2j9NUqsBVqT1LpQ_Rhx1GiE
			Status                 : valid
			OldChallengeAnswer     : [, ]
			ChallengeAnswerMessage :
			HandlerName            : manual
			HandlerHandleDate      : 11/3/2016 12:33:16 AM
			HandlerCleanUpDate     :
			SubmitDate             : 11/3/2016 12:34:48 AM
			SubmitResponse         : {StatusCode, Headers, Links, RawContent...}
			#>

		}



		$certAlias = 'cert-'+[guid]::NewGuid().ToString()

		<# Ready to get the certificate #>
		Write-Output "New-ACMECertificate"
		New-ACMECertificate $domainAliases[0] -Generate -AlternativeIdentifierRefs $domainAliases -Alias $certAlias

		Write-Output "Submit-ACMECertificate"
		Submit-ACMECertificate $certAlias

		<# Pause 10 seconds to wait for LE to create the certificate #>
		Start-Sleep -s 10

		<# Check the status $certAlias #>
		Write-Output "Update-ACMECertificate"
		Update-ACMECertificate $certAlias

		<# Look for a serial number #>


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
		}

		Write-Output "Import certificate via fmsadmin:"
		& $fmsadmin certificate import $certPath -y
		if (! $?) { throw ("fmsadmin certificate import error code " + $LASTEXITCODE) }
		Write-Output "done`r`n"

		Write-Output "Append the intermediary certificate:"
		<# to support older FMS before 15 #>
		Add-Content $serverCustomPath (Get-Content $intermPath)
		Write-Output "done`r`n"

		Write-Output "Stop FileMaker Server:"
		if ($Staging) {
			Write-Output "skipped because -Staging parameter was provided"
		} else {
			$WPEWasRunning = Get-Process fmscwpc -ErrorAction:Ignore
			$FilesWereOpen = & $fmsadmin list files
			& $fmsadmin stop server -y
			if (! $?) { throw ("error code " + $LASTEXITCODE) }
		}
		Write-Output "done`r`n"

		Write-Output "Restart the FMS service:"
		if ($Staging) {
			Write-Output "skipped because -Staging parameter was provided"
		} else {
			Restart-Service "FileMaker Server"
		}
		Write-Output "done`r`n"

		<# Just in case server isn't configured to start automatically
			(should add other services here, if necessary, like WPE) #>
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
			if ($FilesWereOpen -and -not(& $fmsadmin list files)) {
				Write-Output "open files because they were open before FMS was stopped, but aren't now:"
				& $fmsadmin open
			}
		}
		Write-Output "done`r`n"
	}
}

Finally {
	if ( $Logging ) {
		Write-Host "`r`nDelete old Log files, if necessary."
		Get-ChildItem $LogDirectory -Filter *.log | Sort CreationTime -Descending | Select-Object -Skip $LogsToKeep | Remove-Item -Force
		Write-Host
		Stop-Transcript
	}
}
