!include "MUI.nsh"

!define MUI_ICON ".\resources\app-icon.ico"
!define MUI_UNICON ".\resources\app-icon.ico"

Name "drasyl"
InstallDir "$PROGRAMFILES64\drasyl"
OutFile "..\target\release\drasyl_0.1.0_windows.exe"
BrandingText "drasyl"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Section "Install"
	SetOutPath $INSTDIR

	DetailPrint "Stopping drasyl UI if running..."
	ExecWait `taskkill /im drasyl-ui.exe /f`

	DetailPrint "Stopping drasyl service if running..."
	ExecWait 'sc stop drasyl'

	DetailPrint "Waiting for drasyl service to stop..."
	Sleep 5000

	DetailPrint "Stopping drasyl process if running..."
	ExecWait `taskkill /im drasyl.exe /f`

	WriteUninstaller "$INSTDIR\drasyl Uninstaller.exe"

    File ".\resources\wintun\amd64\wintun.dll"
	File "..\target\release\drasyl.exe"
	File "..\target\release\drasyl-ui.exe"
	File ".\resources\app-icon.ico"

	CreateDirectory "$COMMONPROGRAMDATA\drasyl"

	CreateShortCut "$SMPROGRAMS\drasyl UI.lnk" "$INSTDIR\drasyl-ui.exe" "" "$INSTDIR\app-icon.ico"

	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "DisplayName" "drasyl  - secure, software-defined overlay networks, connecting all your devices"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "UninstallString" "$\"$INSTDIR\drasyl Uninstaller.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "InstallLocation" "$\"$INSTDIR$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "HelpLink" "https://drasyl.org"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "URLUpdateInfo" "https://drasyl.org"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "URLInfoAbout" "https://drasyl.org"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "DisplayIcon" "$\"$INSTDIR\app-icon.ico$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "Publisher" "Heiko Bornholdt & Kevin Roebert"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "DisplayVersion" "0.1.0"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "NoModify" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl" "NoRepair" 1

	DetailPrint "Creating drasyl service..."
	ExecWait 'sc create drasyl binpath= "\"$INSTDIR\drasyl.exe\" run-service --log-file $COMMONPROGRAMDATA\drasyl\drasyl.log --log-level trace --config $COMMONPROGRAMDATA\drasyl\config.toml --token $COMMONPROGRAMDATA\drasyl\auth.token" DisplayName= "drasyl" start= auto'
	DetailPrint "Setting drasyl service description..."
	ExecWait 'sc description drasyl "drasyl provides secure, software-defined overlay networks, connecting all your devices."'
	DetailPrint "Starting drasyl service..."
	ExecWait 'sc start drasyl'

SectionEnd

Section "Uninstall"
	DetailPrint "Stopping drasyl service..."
    ExecWait 'sc stop drasyl'
    DetailPrint "Deleting drasyl service..."
    ExecWait 'sc delete drasyl'

	DetailPrint "Waiting for drasyl service to stop..."
	Sleep 5000

	DetailPrint "Terminating drasyl UI process..."
	ExecWait `taskkill /im drasyl-ui.exe /f`

	DetailPrint "Terminating drasyl process..."
	ExecWait `taskkill /im drasyl.exe /f`

	Delete "$SMPROGRAMS\drasyl.lnk"
    Delete "$INSTDIR\app-icon.ico"
    Delete "$INSTDIR\drasyl-ui.exe"
    Delete "$INSTDIR\drasyl.exe"
    Delete "$INSTDIR\wintun.dll"
    Delete "$INSTDIR\drasyl Uninstaller.exe"
    RMDir "$INSTDIR"

	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\drasyl"

    ; Delete "$COMMONPROGRAMDATA\drasyl\drasyl.log"
    ; Delete "$COMMONPROGRAMDATA\drasyl\config.toml"
    ; Delete "$COMMONPROGRAMDATA\drasyl\auth.token"
    ; RMDir "$COMMONPROGRAMDATA\drasyl"
SectionEnd