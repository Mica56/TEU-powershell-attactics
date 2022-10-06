# By Threats Experts University
 
 #T1491.001
$updateWallpapercode = @' 
using System.Runtime.InteropServices; 
namespace Win32{

    public class Wallpaper{ 
        [DllImport("user32.dll", CharSet=CharSet.Auto)] 
         static extern int SystemParametersInfo (int uAction , int uParam , string lpvParam , int fuWinIni) ; 
         
         public static void SetWallpaper(string thePath){ 
            SystemParametersInfo(20,0,thePath,3); 
        }
    }
} 
'@
if (Test-Path -Path $env:TEMP\old.png -PathType Leaf) {
     $orgImg = Get-Content -Path "$env:TEMP\old.png"
     add-type $updateWallpapercode 
     [Win32.Wallpaper]::SetWallpaper($orgImg)
}
Remove-Item "$env:TEMP\old.png" -ErrorAction Ignore
Remove-Item "$env:TEMP\new.png" -ErrorAction Ignore
