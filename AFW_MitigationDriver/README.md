# AFW Mitigation Driver
The folder contains a Mini-Filter Driver which we wrote as a **Proof-of-Concept** which demonstrates how we blocked two Arbitrary File Write vulnerabilities without installing any patches (**Tested on Win10 RS1 x64**):
 - CVE-2020-1048 (Print Spooler)
 - CVE-2019-1069 (Task Scheduler)

---
The Driver is based on Microsoft's Code from here:
https://github.com/microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/scanner
We have added Microsoft Public License to this folder, and this Driver project is released under the original Microsoft license.

---
We believe that the concept MIGHT block more vulnerabilities of the same bug class (Arbitrary File Write), but we can't guarantee it as we didn't test it, and we didn't implement it yet.

## Disclaimer
This is a **Proof-of-Concept**!
- **DO NOT deploy it on a production environment.**
- IT MIGHT contain False Positive / False Negative and might interrupt the OS.
- We did our best following Microsoft's guidelines for writing a Kernel-Mode Mini-Filter Driver, BUT, we can't guarantee that loading the driver won't cause problems as it's only a PoC and not a production system.

## Installation
1. [Build the driver](https://docs.microsoft.com/en-us/windows-hardware/drivers/develop/building-a-driver) using WDK (Windows Driver Kit.) This process can be simplified by also using Visual Studio.
2. In order to test the driver, DSE (Driver Signature Enforcement) must be disabled (unless you will use a valid signature which you pre-installed on your VM.)
3. [Load the driver](https://resources.infosecinstitute.com/loading-the-windows-kernel-driver/) (this can be done in multiple ways, e.g., OSR Driver Loader / sc.exe, ...  )

## Driver Implementation
We used 2 main logics in order to block the vulnerabilities:

1. Restrict any file write operation to System32 by an unprivileged user.
2. Restrict the creation of a hardlink to a privileged path by an unprivileged user.

We'll explain how we implemented each one.

### System32 Unprivileged Write Restriction
Some folders in System32 are writable by unprivileged users. Some of the Arbitrary File Write vulnerabilities' root cause which were reported in the last few years were because of this reason, for example: 
- CVE-2020-1048 - An unprivileged user is allowed to write to System32\spool\PRINTERS, and write a crafted SHD file which exploits the vulnerability.

We implemented a Pre IRP_MJ_CLEANUP callback which validates the following on files with WriteAccess:
1. Whether the user is not NT AUTHORITY\SYSTEM, by extracting the Thread's token's SID and comparing it to SYSTEM's SID.
2. Whether the associated file's path is located within System32\spool\PRINTERS.

If the answer to both question is yes - we deleted the file and returned STATUS_ACCESS_DENIED.

### Hardlink Creation Mitigation
The Hardlink creation is a very common way to exploit some Logic LPE bugs, which was [presented by James Forshaw in 2015](https://googleprojectzero.blogspot.com/2015/12/between-rock-and-hard-link.html).

Some services which runs as NT AUTHORITY\SYSTEM performs elevated file operations on low-privileged user paths, therefore, creating a hardlink from a low-privileged path to a privileged path will cause the service to make privileged operations (such as set its DACL) on an arbitrary file which can be specified by the low-privileged user (the target of the hardlink.)

#### Implementation
0. First, we created a Post IRP_MJ_CREATE callback which checks if the user has a write access to a file. We saved it to a stream handle context.
1. Next, we created a Pre IRP_MJ_SET_INFORMATION callback which only works with the SetFileInformation FileInformationClass. 
   - We know that there are more ways to create a link, but we focused on this one.

2. We then checked whether the user has Write permissions to the target of the link, by extracting this information from the stream handle context.
3. If the user tries to create a hardlink to a path he doesn't have write permissions to, we will block the operation by returning STATUS_ACCESS_DENIED and complete the I/O operation without creating the hardlink.
