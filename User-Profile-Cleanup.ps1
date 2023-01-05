#Server - User Profile Cleanup - Darren Banfi
#Allows to Takecontrol of User Profile folders on a Server to allow Archive / Deletion
#Tested on Windows Server 2012r2 with PowerShell v4.0
#Based on Token Code from unavilable site - http://channel9.msdn.com/Forums/Coffeehouse/Powershell-subinacl-ownership-of-directories
#0.5 05/01/2023 - Added DeleteApp Data Option
#0.4 05/01/2023 - Fixed Roaming Profile Folder Permissions
#0.3 05/01/2023 - Fixed handerling of [] in filename
#0.2 05/01/2023 - Added Path Validation for Folders and Files
#0.1 04/01/2023

#Variables for Setup
#Administrator is the Default Account to use to add permissions to folders, change here for another account with Administrator Rights if required.
$UserAccountForAdmin = "Administrator"
$Version = "0.5"
#Auto Delete App Data - Set to $true to delete AppData Folder after Profile Permissions Changed
$DeleteAppData = $false

#Main Program - Start
Clear-Host
Write-Host "User Profile Cleanup Script " $Version "© Darren Banfi"
Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::`n"
$UsersFolder = Read-Host "Please enter full path of Users Folder (C:\Users\)"

#Check we have a valid folder, if not reprompt
    while ($check -ne "1")
    {
        if (Test-Path -Path $UsersFolder){
         $check = "1"    
        } else {        
        Write-Host "Users Folder Not Found - Please check and reenter valid path"
        $UsersFolder = Read-Host "Please enter full path of Users Folder (C:\Users\)"
        }
    }
#Check we have an ending \ in the Path String - if missing, add it
    if($UsersFolder -match '\\$') {
        Write-Host "Path has been Set"
    } else {
         $UsersFolder = $UsersFolder + "\"
         Write-Host "Path has been set, \ Added"
    }

$TempFolder = 'C:\TempFolder'
$TempFile = 'C:\TempFile'

$code = @"
using System;
using System.Runtime.InteropServices;
 public class TokenManipulator
 {

  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
  ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

  [DllImport("kernel32.dll", ExactSpelling = true)]
  internal static extern IntPtr GetCurrentProcess();

  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
  phtok);

  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name,
  ref long pluid);

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }

  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

  public static bool AddPrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_ENABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }
  }

  public static bool RemovePrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;

    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_DISABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }
  }

 }
"@

add-type $code
$RestorePrivResult = $False
"`nTesting RestorePrivResult initial value = " + $RestorePrivResult

"`nInitial privileges"
whoami /priv | Select-String "seTakeOwnershipPrivilege"

"`nAdding privileges"
$RestorePrivResult = [TokenManipulator]::AddPrivilege("seTakeOwnershipPrivilege") #Necessary to override FilePermissions
"RestorePrivResult = " + $RestorePrivResult
whoami /priv | Select-String "seTakeOwnershipPrivilege"
"Adding privileges"
$RestorePrivResult = [TokenManipulator]::AddPrivilege("SeRestorePrivilege") #Necessary to bypass Traverse Checking
"RestorePrivResult = " + $RestorePrivResult
whoami /priv | Select-String "SeRestorePrivilege"
$RestorePrivResult = [TokenManipulator]::AddPrivilege("SeBackupPrivilege") #Necessary to set Owner Permissions
"RestorePrivResult = " + $RestorePrivResult
whoami /priv | Select-String "SeBackupPrivilege"

#Blank the KeyInput - ready for the first Folder Name
$Keyinput = ""

#***Test Privlages are correct and then continue

while ($Keyinput -ne "END")
{
    $Keyinput = Read-Host "Enter Username of Folder to Take Ownership (john.smith) - END to end"
    $CheckPath = $UsersFolder + $Keyinput
    $checkPH = "0"
        #Check we have a valid folder, if not reprompt until we do, or END
        while ($checkPH -ne "1" -and $Keyinput -ne "END")
        {
            if (Test-Path -Path $CheckPath){
             $checkPH = "1"    
            } else {        
            Write-Host "Folder Not Found - Please check and reenter valid path" + $CheckPath
            $Keyinput = Read-Host "Please enter full name of valid Users Folder (john.smith / john.smith.v6)"
            $CheckPath = $UsersFolder + $Keyinput
            }
        }
    #Main Code to Set the Premissions of the Validated Folder    
    if($Keyinput -ne "END") {
    $Path = $UsersFolder + $Keyinput
    #Set Ownership to Administrator Account
    $ACL = Get-Acl -Path $Path
    $BuiltinAdmin = New-Object System.Security.Principal.Ntaccount($UserAccountForAdmin)
    $ACL.SetOwner($BuiltinAdmin)
    $ACL | Set-Acl -Path $Path
    Get-ACL -Path $Path

    #Do the Rest of the changes to make the Folder files Admin owner as well
    $BuiltinAdminFullControlAcl = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdmin,"FullControl","Allow")

    #region Create temp folder with Admin owner and full control
    $FolderBuiltinAdminOwnerAcl = New-Object System.Security.AccessControl.DirectorySecurity
    $FolderBuiltinAdminOwnerAcl.SetOwner($BuiltinAdmin)
    Remove-Item $TempFolder -EA Ignore
    New-Item -Type Directory -Path $TempFolder
    $TempFolderAcl = Get-Acl -Path $TempFolder
    $TempFolderAcl.SetAccessRule($BuiltinAdminFullControlAcl)
    #Set Root Folder - Administrator Permissions (for older style Profiles)
    Set-Acl -Path $Path -AclObject $TempFolderAcl
    #region Change folder owners to Admin
    $Folders = @(Get-ChildItem -Path $Path -Force -Directory -Recurse)
    foreach ($Folder in $Folders) {
        $Folder.SetAccessControl($FolderBuiltinAdminOwnerAcl)
        Set-Acl -Path $Folder.FullName -AclObject $TempFolderAcl
    }
    #region Create temp file with Admin owner and full control
    $FileBuiltinAdminOwnerAcl = New-Object System.Security.AccessControl.FileSecurity
    $FileBuiltinAdminOwnerAcl.SetOwner($BuiltinAdmin)

    Remove-Item $TempFile -EA Ignore
    New-Item -Type File -Path $TempFile

    $TempFileAcl = Get-Acl -Path $TempFile
    $TempFileAcl.SetAccessRule($BuiltinAdminFullControlAcl)

    $Files = @(Get-ChildItem -Path $Path -Force -File -Recurse)

    foreach ($File in $Files) {
    $File.SetAccessControl($FileBuiltinAdminOwnerAcl)
    Set-Acl -Path $File.FullName.toString() -AclObject $TempFileAcl
    }
#Delete App Data Folder if Flag is True
    if ($DeleteAppData -eq $true){
        $appDataPath = $Path + "\AppData"
        if (Test-Path -Path $appDataPath){Remove-Item $appDataPath -Recurse -Force -ErrorAction Ignore}
    }
    Remove-Item $TempFile, $TempFolder
    Write-Host "Processed : " $CheckPath "`n"
}

}

#END has been Typed - Lets end the Process
"`nRemoving privileges just added"
$RestorePrivResult = [TokenManipulator]::RemovePrivilege("seTakeOwnershipPrivilege")
"RestorePrivResult = " + $RestorePrivResult
whoami /priv | Select-String "seTakeOwnershipPrivilege"
$RestorePrivResult = [TokenManipulator]::RemovePrivilege("SeRestorePrivilege")
"RestorePrivResult = " + $RestorePrivResult
whoami /priv | Select-String "seTakeOwnershipPrivilege"
$RestorePrivResult = [TokenManipulator]::RemovePrivilege("SeBackupPrivilege")
"RestorePrivResult = " + $RestorePrivResult
whoami /priv | Select-String "seTakeOwnershipPrivilege"
WRITE-HOST "`nUser Cleanup Program Ended"
