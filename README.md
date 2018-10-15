## Credit

This is a fork of the work started by: [David Nahodyl, Blue Feather](http://bluefeathergroup.com/blog/how-to-use-lets-encrypt-ssl-certificates-with-filemaker-server/)  

Thanks for figuring out the hard part David!


## Notes

* Only supports newer OS (only tested on Windows Server 2016).
* Only tested on FileMaker Server 17.
* Installs ACMESharp for you.
* Will not display any errors, unless it fails.


## Installation

1. Open PowerShell console as an Administrator:
    1. Click **Start**
    2. Type **PowerShell**
    3. Right-click on **Windows PowerShell**
    4. Click **Run as administrator**

2. Download the `GetSSL.ps1` file to your server:

   `Invoke-WebRequest -Uri https://raw.githubusercontent.com/dansmith65/FileMaker-LetsEncrypt-Win/master/GetSSL.ps1 -OutFile "C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1"`

3. Get your first Certificate:
   This is necessary because the first time you run the script, it will likely update NuGet and install ACMESharp, both of which require confirmation.  
   You **should** read the Docs first (see below). If you like to live dangerously and you have FileMaker Server installed in the default directory you can run this command after replacing `fms.example.com` and `user@email.com` with your own.  
   Consider adding the `-Staging` parameter when first configuring this script, so you can verify there are no permissions or config issues before using Let's Encrypt production server, or restarting FileMaker server.

   `powershell.exe -ExecutionPolicy Bypass -NoExit -Command "& 'C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1' fms.example.com user@email.com"`

4. (Optional) Setup scheduled task to renew the certificate:  
   Will schedule a task to re-occur every 63 days. You can modify this task after it's created by opening Task Scheduler. If you don't do this step, you will have to run the above command to renew the certificate before it expires every 90 days.

   `powershell.exe -ExecutionPolicy Bypass -NoExit -Command "& 'C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1' fms.example.com user@email.com -ScheduleTask"`

   To have this script run silently, it must also be able to perform fmsadmin.exe without asking for username and password. There are two ways to do that:

   1. Add a group name that is allowed to access the Admin Console and run the script as a user that belongs to the group.
   2. Hard-code the username and password into this script. (less secure)  
      Add "-u youruser -p yourpass" at the end of any line containing `$fmsadmin`, that requires authentication (import certificate, list files, stop server, open).



## Documentation

If you view the [GetSSL.ps1](GetSSL.ps1) file as text; the documentation is in comments at the top of the file.

To view it the "PowerShell Way", you can use Get-Help like:

```powershell
Get-Help .\GetSSL.ps1 -full
```



## Staging

I won't duplicate what is already said about the `-Staging` parameter in the official help docs but I do want to add to it. Let's Encrypt service imposes [Rate Limits](https://letsencrypt.org/docs/rate-limits/), which are less restrictive on their staging environment. While developing this script (and before I added this parameter) I repeatedly tested with the same domain and quickly hit the limit of 5 identical certificate requests per week. While this won't pertain to most people, I do want to point out that if you are doing testing, you _should_ use the `-Staging` parameter.

Using this parameter is a great way of doing the initial setup/testing as well. It allows you to go through all the steps without worrying about Rate Limits or your server being restarted. Common issues like permissions to call fmsadmin.exe without having to type a user/pass can be resolved before doing a final install. Since the existing certificate is backed up before being replaced, you could always restore to existing configuration, if needed.



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
powershell.exe -ExecutionPolicy Bypass -NoExit -Command `
    "& 'C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1' example.com, www.example.com, fms.example.com user@email.com"
```



## Custom Shutdown/Startup

This script must restart the FileMaker Server process to complete the installtion of the certificate. It does it's best to do a safe shutdown and to start the server, CWP (if it was running), and open files (if there were any open before). However, if you want to customize this process, you could edit the script towards the end where it does these steps. A likely example is if you want to give users longer than 30 seconds to close files before the server restarts. To do that, you would add ` -t #` with the number of seconds timeout you want after: `fmsadmin stop server -y`.

Beware that if you have to enter an encryption at rest password when you open files, you will need to manage this process yourself, in this section of the script. NOTE: this only applies if you've configured your server not to store the password.

Alternatively, if you have your own shutdown/startup scripts already, you could call them directly and remove the default steps provided in this script.
