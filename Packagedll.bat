"C:\Program Files\MRE_SDK\tools\DllPackage.exe" "D:\MyGitHub\mre_des_tools\mre_des_tools.vcproj"
if %errorlevel% == 0 (
 echo postbuild OK.
  copy mre_des_tools.vpp ..\..\..\MoDIS_VC9\WIN32FS\DRIVE_E\mre_des_tools.vpp /y
exit 0
)else (
echo postbuild error
  echo error code: %errorlevel%
  exit 1
)

