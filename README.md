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
   You **should** read the Docs first (see below). If you like to live dangerously and you have FileMaker Server installed in
   the default directory you can run this command after replacing `fms.example.com` and `user@email.com` with your own.

    `powershell.exe -ExecutionPolicy Bypass -NoExit -Command "& 'C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1' fms.example.com user@email.com"`

4. (Optional) Setup scheduled task to renew the certificate:  
   Will schedule a task to re-occur every 80 days. You can modify this task after it's created by opening Task Scheduler.  
   If you don't do this step, you will have to run the above command to renew the certificate before it expires every 90 days.

    `powershell.exe -ExecutionPolicy Bypass -NoExit -Command "& 'C:\Program Files\FileMaker\FileMaker Server\Data\Scripts\GetSSL.ps1' fms.example.com user@email.com -ScheduleTask"`

   To have this script run silently, it must also be able to perform fmsadmin.exe without asking for username and password. There are two ways to do that:

    1. Add a group name that is allowed to access the Admin Console and run the script as a user that belongs to the group.
    2. Hard-code the username and password into this script. (less secure)  
       Add "-u username -p password" at the end of the line containing: `fmsadmin certificate import`



## Docs

Once the script is downloaded, run this from PowerShell, while in the same directory as the script, to get all documentation on the script:

```powershell
Get-Help .\GetSSL.ps1 -full
```

(Or just view the GetSSL.ps1 file in a text editor)
