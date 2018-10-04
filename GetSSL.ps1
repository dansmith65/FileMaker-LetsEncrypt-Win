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

$fmsadmin = $FMSPath + 'Database Server\fmsadmin.exe'


function Test-Administrator
{
	$user = [Security.Principal.WindowsIdentity]::GetCurrent()
	(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}


<# Display user input #>
Get-Date
Write-Output ""
Write-Output ('  domains:   '+($Domains -join ', '))
Write-Output "  email:     $Email"
Write-Output "  FMSPath:   $FMSPath"
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
	if ($Time.Date -eq (Get-Date).Date) {
		#Date contained in Time parameter was today, so add IntervalDays
		$Time = $Time.AddDays($IntervalDays)
	}
	if ($PSCmdlet.ShouldProcess(
		"Schedule a task to renew the certificate every $IntervalDays days starting ${Time}", #NOTE: shown with -WhatIf parameter
		"NOTE: If the fmsadmin.exe command cannot run without having to type the username/password when this script is run, the task will fail.",
		"Schedule a task to renew the certificate every $IntervalDays days starting ${Time}?"
	)) {
		$Action = New-ScheduledTaskAction `
			-Execute powershell.exe `
			-Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File '$($MyInvocation.MyCommand.Path)' -Domains $Domains -Email $Email -FMSPath '$FMSPath' -Confirm:0 | Out-File `$env:temp\GetSSL.log"

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



if ($PSCmdlet.ShouldProcess(
	"Replace FileMaker Server Certificate with one from Let's Encrypt, then restart FileMaker Server service.", #NOTE: shown with -WhatIf parameter
	"If you proceed, and this script is successful, FileMaker Server service will be restarted and ALL USERS DISCONNECTED.",
	"Replace FileMaker Server Certificate with one from Let's Encrypt?"
	)) {

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
	if (!(Get-ACMEVault)) {
		Write-Output "Initialize-ACMEVault"
		Initialize-ACMEVault
	}
	#Initialize-ACMEVault -BaseURI https://acme-staging.api.letsencrypt.org/


	Write-Output "Register contact info with LE"
	New-ACMERegistration -Contacts mailto:$Email -AcceptTos


	<# ACMESharp creates a web.config that doesn't work so let's SkipLocalWebConfig and make our own
		(it seems to think text/json is required) #>
	$webConfigPath = $FMSPath + 'HTTPServer\conf\.well-known\acme-challenge\web.config'

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
	$keyPath = $FMSPath + 'CStore\serverKey.pem'
	if (Test-Path $keyPath) {
		Remove-Item $keyPath
	}
	Get-ACMECertificate $certAlias -ExportKeyPEM $keyPath

	Write-Output "Export the certificate"
	$certPath = $FMSPath + 'CStore\crt.pem'
	if (Test-Path $certPath) {
		Remove-Item $certPath
	}
	Get-ACMECertificate $certAlias -ExportCertificatePEM $certPath

	Write-Output "Export the Intermediary"
	$intermPath = $FMSPath + 'CStore\interm.pem'
	if (Test-Path $intermPath) {
		Remove-Item $intermPath
	}
	Get-ACMECertificate $certAlias -ExportIssuerPEM $intermPath


	Write-Output "Import certificate via fmsadmin:"
	& $fmsadmin certificate import $certPath -y
	if (! $?) {
		throw ("fmsadmin certificate import error code " + $LASTEXITCODE)
	}
	Write-Output "done`r`n"

	<# Append the intermediary certificate to support older FMS before 15 #>
	Add-Content $FMSPath'CStore\serverCustom.pem' (Get-Content $intermPath)


	Write-Output "Restart the FMS service:"
	net stop 'FileMaker Server'
	net start 'FileMaker Server'
	Write-Output "done`r`n"

	<# Just in case server isn't configured to start automatically
		(should add other services here, if necessary, like WPE) #>
	Write-Output "Start FileMaker Server:"
	& $fmsadmin start server
	if ($LASTEXITCODE -eq 10006) {
		Write-Output "(If server is set to start automatically, error 10006 is expected)"
	}
	Write-Output "done`r`n"
}
