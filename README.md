## Credit

This is a fork of the work started by: [David Nahodyl, Blue Feather](http://bluefeathergroup.com/blog/how-to-use-lets-encrypt-ssl-certificates-with-filemaker-server/)  

Thanks for figuring out the hard part David!



## Notes

* Only supports newer OS (only tested on Windows Server 2016).
* Only tested on FileMaker Server 18.
  * TODO: did I test on 17 yet?
* Installs all dependencies for you.



## Installation and Quick Setup

1. Open PowerShell console as an Administrator:

   1. Click **Start**
   2. Type **PowerShell**
   3. Right-click on **Windows PowerShell**
   4. Click **Run as administrator**

2. Download the `GetSSL.ps1` file to your server:

   ```powershell
   Invoke-WebRequest `
     -Uri https://raw.githubusercontent.com/dansmith65/FileMaker-LetsEncrypt-Win/master/GetSSL.ps1 `
     -OutFile "C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1"
   ```

3. Install Dependencies:

   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force;
   & 'C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1'
   ```

   After this task completes, you'll be asked if you want to get a certificate, at which point you'll be prompted for domain(s) and email. Then, you'll be asked if you want to schedule a task. If you do all these steps, the setup is complete for this server.

4. (Optional) Email Log File:  

   Store credentials and SMTP info so this script can send logs when it runs from a scheduled task.

   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force;
   & 'C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1' -ConfigureEmail
   ```



## Advanced Options

Examples in this section will use a shortened syntax and assumes you will set execution policy manually, or prefix the command with the snippets above. It also leaves the path to GetSSL.ps1 off for the same reason.

1. Get and Install a Certificate:  
   Also use this command to modify the stored domain or email, which is used for renewals. Once this is done, you likely never have to specify domain/email again unless you want to change it.

   ```powershell
   .\GetSSL.ps1 -Setup -Domains fms.example.com, fms.example2.com -Emails user@email.com, user2@email.com
   ```

2. Renew Certificate:  
   Renew the most recently used certificate. This is the command called by the scheduled task, but you can run it manually if needed.

   ```powershell
   .\GetSSL.ps1 -Renew
   ```

3. Install Certificate:  
   Installs the most recently retrieved certificate. Useful if a certificate was successfully retrieved, but something failed before it was installed.

   ```powershell
   .\GetSSL.ps1 -InstallCertificate
   ```

4. Setup scheduled task to renew the certificate:  
   Will schedule a task to re-occur every 63 days. You can modify this task after it's created by opening Task Scheduler. If you don't do this step, you will have to manually renew the certificate before it expires every 90 days.  

   ```powershell
   .\GetSSL.ps1 -ScheduleTask
   ```

   Note that 63 days was choosens as the default renwal interval because it will make the renewal fall on the same day of the week and is close to the recommended renewal point which is 2/3 of the certificates lifespan. You can specify your own renewal interval by appending: `-IntervalDays 70`, or just manually modify the task via **Task Scheduler**.

   You can also specify your preferred renewal time by appending: `-Time 2:00am`. The default time is **4:00am**.

   A full example with custom interval and time:

   ```powershell
   .\GetSSL.ps1 -ScheduleTask -IntervalDays 70 -Time 2:00am
   ```

5. Update Dependencies:

   ```powershell
   .\GetSSL.ps1 -InstallDependencies -Force
   ```

6. Call [Posh-ACME](https://github.com/rmbolger/Posh-ACME/wiki/(Advanced)-Manual-HTTP-Challenge-Validation) functions directly.  
   You could potentially do this to modify the domains or your contact email. GetSSL will use whatever domains are returned by `Get-PAOrder` and whatever account is returned by `Get-PAAccount`.



## Documentation

If you view the [GetSSL.ps1](GetSSL.ps1) file as text; the documentation is in comments at the top of the file.

To view it the "PowerShell Way", you can use Get-Help like:

```powershell
Get-Help .\GetSSL.ps1 -full
```



## Authentication

This script will seamlessly and securely manage authentication for you. If external authentication is setup for the user the script is run as to access the Admin Console, then that will be used. If it's not, you will be asked for your Admin Console Sign In when the script runs. These credentials will be stored in Windows Credential Manager; the same place FileMaker Server stores your encryption at rest password. The next time the script runs, it will load the stored credentials from Credential Manager.

I haven't tested this scenario but the credentials can probably only be retrieved by the same user account that created them. If you modify your scheduled task to run as a different user, that might break this feature.

If you want to, external authentication can easily be enabled on a default installation of FileMaker Server and does not require an Active Directory:

1. Log in to FileMaker Server 17 admin console
2. Administration > External Athentication > External Accounts for Admin Console Sign In: click __Change__
3. Add a group name and click __Save Authentication Settings__  
   (default install of Windows should work with "Administrators" as the group name)
4. Admin Console Sign In > External Accounts: __Enable__
5. Confirm it's working by typing this on the command line: `fmsadmin list files`. If you are not asked for a user/pass, then it has be properly enabled.

If external authentication _is_ enabled but you _don't_ want to use it, you can store credentials with this command:

```powershell
Get-Credential | New-StoredCredential -Target "GetSSL FileMaker Server Admin Console" -Persist LocalMachine
```



## Staging

I won't duplicate what is already said about the `-Staging` parameter in the official help docs but I do want to add to it. Let's Encrypt service imposes [Rate Limits](https://letsencrypt.org/docs/rate-limits/), which are less restrictive on their staging environment. While developing this script (and before I added this parameter) I repeatedly tested with the same domain and quickly hit the limit of 5 identical certificate requests per week. While this won't pertain to most people, I do want to point out that if you are doing testing, you _should_ use the `-Staging` parameter.

Using this parameter is a great way of doing the initial setup/testing as well. It allows you to go through all the steps without worrying about rate limits or your server being restarted. Common issues like permissions to call fmsadmin.exe without having to type a user/pass can be resolved before doing a final install. Since the existing certificate is backed up before being replaced, you could always restore to existing configuration, if needed.



## Restoring a Certificate

Before replacing any files in the CStore directory, they are backed up in a sub-folder with the current date/time and no backups are ever overwritten or deleted by this script. If you need to restore a previously installed certificate, you can do it with a command like this:

```powershell
Remove-Item "C:\Program Files\FileMaker\FileMaker Server\CStore\serverKey.pem"
fmsadmin certificate import `
    "C:\Program Files\FileMaker\FileMaker Server\CStore\Backup\2018-10-09_181822\serverCustom.pem" `
    --keyfile "C:\Program Files\FileMaker\FileMaker Server\CStore\Backup\2018-10-09_181822\serverKey.pem" -y
```

_Make sure to use the actual path to the backup you want to restore; this code is an example for a backup taken at the time of writing this documentation._



## Multiple Domains

You can request a certificate for multiple domains at once by separating them with commas:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force;
& 'C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1' example.com, www.example.com, fms.example.com user@email.com
```



## Custom Shutdown/Startup

This script must restart the FileMaker Server process to complete the installtion of the certificate. It does it's best to do a safe shutdown and to start the server, CWP (if it was running), and open files (if there were any open before). However, if you want to customize this process, you could edit the script towards the end where it does these steps. A likely example is if you want to give users longer than 30 seconds to close files before the server restarts. To do that, you would add ` -t #` with the number of seconds timeout you want after: `fmsadmin stop server -y`.

Beware that if you have to enter an encryption at rest password when you open files, you will need to manage this process yourself, in this section of the script. NOTE: this only applies if you've configured your server not to store the password.

Alternatively, if you have your own shutdown/startup scripts already, you could call them directly and remove the default steps provided in this script.
