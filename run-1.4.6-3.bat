::2012/07/16 V1.0
::2012/10/01 V1.1 
::2012/10/03 V1.2
::2012/10/16 V1.3
::2012/10/29 V1.4
::2012/11/30 V1.4.2
::2012/12/10 V1.4.3
::2013/01/16 V1.4.4
::2013/04/25 V1.4.4-2
::2013/7/4 V1.4.4-3
::2013/7/4 V1.4.5  MBSA
::2013/9/10 V1.4.6  screensave ; accesscheck ; BrowserHistoryViewer
::2013/9/11 V1.4.6.1 mbsa problem ; reg HKCU
::2013/10/1 V1.4.6.2 rawcopy problem  ; usp problem

::ACER Forensic info gather tool V.1.4
::Writed by ACER TONY

@echo off

echo "                                                      "
echo "  _____                    ___________    .___        "
echo " /  _  \   ____  __________\_   _____/  __| _/____    "
echo "/  /_\  \_/ ___\/ __ \_  __ \    __)_  / __ |/ ___\   "
echo "/    |    \  \__\  ___/|  | \/        \/ /_/ \  \___  "
echo "\____|__  /\___  >___  >__| /_______  /\____ |\___  > "
echo "       \/     \/    \/             \/      \/    \/   "
echo "                                    AF V1.4.6.1       "

::Get OS version
::wmic os get Caption,CSDversion,OSArchitecture /value
::for /f "delims=" %%a in ('wmic os get Caption,CSDversion,OSArchitecture /value') do @echo %%a

for /f "delims=" %%a in ('wmic os get Caption') do if not %%a LSS "" set A_OS_Caption=%%a
for /f "delims=" %%a in ('wmic os get CSDversion') do if not %%a LSS "" set A_OS_CSDversion=%%a
for /f "delims=" %%a in ('wmic os get OSArchitecture') do if not %%a LSS "" set A_OS_OSArchitecture=%%a

@echo OS: %A_OS_Caption% 
@echo Version: %A_OS_CSDversion%
@echo Architecture: %A_OS_OSArchitecture%

::if %A_OS_CSDversion% EQU "64-bit" goto X64
::if %A_OS_CSDversion% EQU "32-bit" goto X32

::Get date of today 
set A_today=%date:~0,4%.%date:~5,2%.%date:~8,2%


::Mkdir dir in current dir
echo. 
echo. 
echo ::Mkdir dir name: %~dp0\%A_today%_%USERDOMAIN%_%computername%
set A_forensic_data_dir=%~dp0\%A_today%_%USERDOMAIN%_%computername%
if not exist %A_forensic_data_dir%  mkdir %A_forensic_data_dir%

::Dump MFT
echo ::Dump MFT
if not exist %A_forensic_data_dir%\MFT  mkdir %A_forensic_data_dir%\MFT
%~dp0\rawcopy C:0 %A_forensic_data_dir%\MFT
 

::Analysis MFT
echo.
echo :: Analysis MFT
%~dp0\analyzeMFT -f "%A_forensic_data_dir%\MFT\$MFT" -o %A_forensic_data_dir%\MFT\C_MFT.csv

::mkdir GP
if not exist %A_forensic_data_dir%\GP mkdir %A_forensic_data_dir%\GP

echo %A_OS_Caption% | findstr /C:"Windows XP"
::echo XP_errorlevel =  %errorlevel%
if %errorlevel% == 0 goto WindowsXP

echo %A_OS_Caption% | findstr /C:"Windows 7"
::echo 7_errorlevel =  %errorlevel%
if %errorlevel% == 0 goto Windows7

echo %A_OS_Caption% | findstr /C:"2003"
::echo 2003_errorlevel =  %errorlevel%
if %errorlevel% == 0 goto Windows2003

echo %A_OS_Caption% | findstr /C:"2008"
::echo 2008_errorlevel =  %errorlevel%
if %errorlevel% == 0 goto Windows2008



:WindowsXP
echo :: run Windows XP mode
if exist C:\windows\tasks\SCHEDLGU.txt  copy C:\windows\tasks\SCHEDLGU.txt  %A_forensic_data_dir%
if not exist C:\windows\tasks\SCHEDLGU.txt copy C:\windows\SCHEDLGU.txt  %A_forensic_data_dir%
if not exist  %A_forensic_data_dir%  mkdir  %A_forensic_data_dir%\tasks
xcopy C:\Windows\Tasks  %A_forensic_data_dir%\tasks /s /I /y /h

::Dump Windows XP event log
echo ::Dump Windows XP event log
if not exist %A_forensic_data_dir%\Evtx mkdir %A_forensic_data_dir%\Evtx
%~dp0\psloglist.exe /accepteula -g %A_forensic_data_dir%\Evtx\app.evt application
%~dp0\psloglist.exe /accepteula -g %A_forensic_data_dir%\Evtx\system.evt system
%~dp0\psloglist.exe /accepteula -g %A_forensic_data_dir%\Evtx\security.evt security
goto :Phase2

:Windows2003
echo ::run Windows 2003 mode
if exist C:\windows\tasks\SCHEDLGU.txt  copy C:\windows\tasks\SCHEDLGU.txt  %A_forensic_data_dir%
if not exist  %A_forensic_data_dir%  mkdir  %A_forensic_data_dir%\tasks
xcopy C:\Windows\Tasks  %A_forensic_data_dir%\tasks /s /I /y /h

::Dump Windows 2003 event log
echo ::Dump Windows 2003 event log
if not exist %A_forensic_data_dir%\Evtx mkdir %A_forensic_data_dir%\Evtx
%~dp0\psloglist.exe /accepteula -g %A_forensic_data_dir%\Evtx\app.evt application
%~dp0\psloglist.exe /accepteula -g %A_forensic_data_dir%\Evtx\system.evt system
%~dp0\psloglist.exe /accepteula -g %A_forensic_data_dir%\Evtx\security.evt security


goto :Phase2

:Windows7
echo ::run Windows 7 mode
if exist C:\windows\tasks\SCHEDLGU.txt  copy C:\windows\tasks\SCHEDLGU.txt  %A_forensic_data_dir%
if not exist  %A_forensic_data_dir%  mkdir  %A_forensic_data_dir%\tasks
xcopy C:\Windows\Tasks  %A_forensic_data_dir%\tasks /s /I /y /h

::Dump Windows 7  event log
echo ::Dump Windows 7  event log
if not exist %A_forensic_data_dir%\Evtx mkdir %A_forensic_data_dir%\Evtx
::wevtutil epl security %A_forensic_data_dir%\Evtx\security.evtx
::wevtutil epl application %A_forensic_data_dir%\Evtx\application.evtx
::wevtutil epl system %A_forensic_data_dir%\Evtx\system.evtx

xcopy C:\Windows\System32\winevt %A_forensic_data_dir%\Evtx\  /H /E /Q

auditpol /get /category:*  > %A_forensic_data_dir%\GP\auditpol.log


goto :Phase2

:Windows2008
echo ::run Windows 2008 mode
if exist C:\windows\tasks\SCHEDLGU.txt  copy C:\windows\tasks\SCHEDLGU.txt  %A_forensic_data_dir%
if not exist  %A_forensic_data_dir%  mkdir  %A_forensic_data_dir%\tasks
xcopy C:\Windows\Tasks  %A_forensic_data_dir%\tasks /s /I /y /h

::Dump Windows 2008 event log
echo ::Dump Windows 2008 event log
if not exist %A_forensic_data_dir%\Evtx mkdir %A_forensic_data_dir%\Evtx
::wevtutil epl security %A_forensic_data_dir%\Evtx\security.evtx
::wevtutil epl application %A_forensic_data_dir%\Evtx\application.evtx
::wevtutil epl system %A_forensic_data_dir%\Evtx\system.evtx
xcopy C:\Windows\System32\winevt %A_forensic_data_dir%\Evtx\  /H /E /J /Q
auditpol /get /category:*  > %A_forensic_data_dir%\GP\auditpol.log


goto :Phase2




:Phase2
echo.
echo.
echo.
echo Runing Phase2 ...
echo.
echo.
echo.

::Gather IP info
echo ::Gather IP info
set A_Info_filename=%A_forensic_data_dir%\info.txt
ipconfig > %A_Info_filename%
echo \n >> %A_Info_filename%
set >>  %A_Info_filename%
echo \n >> %A_Info_filename%
systeminfo >> %A_Info_filename%

::ipconfig /displaydns 
echo ::ipconfig /displaydns 
ipconfig /displaydns > %A_forensic_data_dir%\ipconfig.displaydns.log

::list user info
echo ::list user info
echo local administrators > %A_forensic_data_dir%\user.log
echo. >> %A_forensic_data_dir%\user.log
net localgroup "administrators" >> %A_forensic_data_dir%\user.log
echo. >> %A_forensic_data_dir%\user.log


echo net user >> %A_forensic_data_dir%\user.log
echo. >> %A_forensic_data_dir%\user.log
net user >> %A_forensic_data_dir%\user.log
echo. >> %A_forensic_data_dir%\user.log

echo domain admins >> %A_forensic_data_dir%\user.log
net group "domain admins" /domain >> %A_forensic_data_dir%\user.log
echo. >> %A_forensic_data_dir%\user.log

::list deatil user info
echo ::list deatil user info

::for /F "skip=1" %%c  in (' wmic useraccount get name ') do net user %%c  >>  %A_forensic_data_dir%\detail.user.log

::for /F "skip=1" %%c  in (' wmic useraccount get name ') do net user %%c /domain >>  %A_forensic_data_dir%\detail.user.log

::user sid 
::echo ::Get user sid info

wmic /output:"%A_forensic_data_dir%\wmic.useraccount.log" useraccount list Full 
wmic /output:"%A_forensic_data_dir%\wmic.group.log" group list Full

::Installed Program 
echo ::Get Installed Program
wmic /output:"%A_forensic_data_dir%\Installed_Program.log" product list full

:: secedit
secedit /export /cfg %A_forensic_data_dir%\GP\%computername%.gp.ini /log %A_forensic_data_dir%\GP\%computername%.gp.log 
secedit /analyze /db  %A_forensic_data_dir%\GP\%computername%.gp.db  /cfg %A_forensic_data_dir%\GP\%computername%.gp.ini /log %A_forensic_data_dir%\GP\%computername%.gp.log 

::auditpol
auditpol /get /category:* >  %A_forensic_data_dir%\GP\%computername%.audit.log

::Gather Volume C  file list
echo ::gather Volume C  file list ..
dir /a /s /tc /q C:\ >  %A_forensic_data_dir%\C_file_a.s.tc.q.log
::dir /a /s /q  C:\  > %A_forensic_data_dir%\C_file.a.s.q.log

:: run autoruns
echo ::run autoruns
::%~dp0\autorunsc.exe /accepteula -a -c -m -v  * > %A_forensic_data_dir%\autorun_verified.csv 
start /MIN /wait /B "" "%~dp0\autoruns.exe" /accepteula -v -a %A_forensic_data_dir%\%computername%_autorun_verified.arn

::run process explorer
echo ::run command line pocess explorer
%~dp0\listdlls /accepteula -v > %A_forensic_data_dir%\listdll.log 
%~dp0\pslist /accepteula -t > %A_forensic_data_dir%\pslist.log 
%~dp0\handle.exe /accepteula  -a > %A_forensic_data_dir%\handle.log

::Dump Hive
echo ::Dump Hive 
if not exist %A_forensic_data_dir%\Hive mkdir %A_forensic_data_dir%\Hive 
reg save HKLM\SYSTEM %A_forensic_data_dir%\Hive\system
reg save HKLM\SECURITY %A_forensic_data_dir%\Hive\security
reg save HKLM\SAM %A_forensic_data_dir%\Hive\sam
reg save HKLM\SOFTWARE %A_forensic_data_dir%\Hive\software
reg save HKCU %A_forensic_data_dir%\Hive\hkcu

::goto regripper


::Reg Ripper
:regripper



::RootKit Check

::DumpMemory

::tcpview

::prefetch
if not exist %A_forensic_data_dir%\Pefetch mkdir %A_forensic_data_dir%\Prefetch
xcopy C:\Windows\Prefetch  %A_forensic_data_dir%\Prefetch\ /H /E /J /Q



::arp table
echo ::dump arp
arp -a > %A_forensic_data_dir%\arp.txt

::/etc/hosts
echo ::dump hosts
if not exist %A_forensic_data_dir%\HOSTS mkdir  %A_forensic_data_dir%\HOSTS
xcopy C:\windows\system32\drivers\etc\hosts %A_forensic_data_dir%\HOSTS\ /H /E /J /Q 

::usb
if not exist %A_forensic_data_dir%\USB mkdir %A_forensic_data_dir%\USB
if exist C:\windows\inf\setupapi.dev.log xcopy C:\windows\inf\setupapi.dev.log %A_forensic_data_dir%\USB\   
if exist C:\windows\setupapi.log xcopy C:\windows\inf\setupapi.log %A_forensic_data_dir%\USB\
if exist C:\windows\inf\setupapi.app.log xcopy C:\windows\inf\setupapi.app.log %A_forensic_data_dir%\USB\
if exist C:\windows\inf\setupapi.offline.log xcopy C:\windows\inf\setupapi.offline.log %A_forensic_data_dir%\USB\

%~dp0\usp -livesys -csv -separator "," > %A_forensic_data_dir%\USB\usb.log 


::BrowsingHistory 
if not exist %A_forensic_data_dir%\BrowserHV mkdir %A_forensic_data_dir%\BrowserHV
%~dp0\BrowsingHistoryView.exe /scomma %A_forensic_data_dir%\BrowserHV\browser_history.csv /SaveDirect  /HistorySource 1 /VisitTimeFilterType 1


::net use
echo. 
echo :Net use:
if not exist %A_forensic_data_dir%\Net mkdir %A_forensic_data_dir%\Net
net use >> %A_forensic_data_dir%\Net\net.use.log



::net share
echo. 
echo :Net share:
if not exist %A_forensic_data_dir%\Net mkdir %A_forensic_data_dir%\Net
net share >> %A_forensic_data_dir%\Net\net.share.log

::net session
echo. 
echo :Net session:
if not exist %A_forensic_data_dir%\Net mkdir %A_forensic_data_dir%\Net
net sessions /list >> %A_forensic_data_dir%\Net\net.session.log

::net account
echo. 
echo :Net Accounts:
if not exist %A_forensic_data_dir%\Net mkdir %A_forensic_data_dir%\Net
net accounts >> %A_forensic_data_dir%\Net\net.account.log

::service
%~dp0\psservice /accepteula query  > %A_forensic_data_dir%\%computername%_psservice.log
%~dp0\psservice /accepteula security > %A_forensic_data_dir%\%computername%_psservice.sec.log


::mbsa
::run mbsa
::copy %A_forensic_data_dir%\wsusscn2.cab %temp%
if not exist %A_forensic_data_dir%\mbsa mkdir %A_forensic_data_dir%\mbsa
%~dp0\mbsacli /xmlout /unicode /nvc /catalog %~dp0\wsusscn2.cab > %A_forensic_data_dir%\mbsa\%computername%.mbsa.xml
::del %temp%\wsusscn2.cab


::hidden file
dir /AH /4 /S /TC C:\ > %A_forensic_data_dir%\Hidden_file.txt

::scan virus --

::virus record

::screensave
echo ::screensave check
reg query "HKCU\Control Panel\Desktop" > %A_forensic_data_dir%\GP\reg_screenave.log

::Run subinacl
echo ::check privilege ...
%~dp0\subinacl /outputlog=%A_forensic_data_dir%/%computername%_service.log /testmode /service * /display
%~dp0\accesschk /accepteula -c * > %A_forensic_data_dir%/%computername%_acesschk_service.log

::run 7z
echo.
echo Packing...
%~dp0\7za a -r -pP@ssw0rd %A_forensic_data_dir%.7z %A_forensic_data_dir%
::7za t -pacerTGB! %A_forensic_data_dir%.7z

::remove dir

rmdir  /S /Q %A_forensic_data_dir%

::finish
echo.
echo ::Finish !!!

:finish
::clean set data
set A_today=
set A_forensic_data_dir=
set A_Info_filename=
set A_OS_Caption=
set A_OS_CSDversion=
set A_OS_OSArchitecture=
