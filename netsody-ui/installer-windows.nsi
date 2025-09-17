!include "MUI.nsh"

!define MUI_ICON ".\resources\app-icon.ico"
!define MUI_UNICON ".\resources\app-icon.ico"

Name "Netsody"
InstallDir "$PROGRAMFILES64\Netsody"
OutFile "..\target\release\Netsody_0.1.0_windows.exe"
BrandingText "Netsody"

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

	DetailPrint "Stopping Netsody UI if running..."
	ExecWait `taskkill /im netsody-ui.exe /f`

	DetailPrint "Stopping Netsody service if running..."
	ExecWait 'sc stop netsody'

	DetailPrint "Waiting for Netsody service to stop..."
	Sleep 5000

	DetailPrint "Stopping Netsody process if running..."
	ExecWait `taskkill /im netsody.exe /f`

	WriteUninstaller "$INSTDIR\netsody uninstaller.exe"

    File ".\resources\wintun\amd64\wintun.dll"
	File "..\target\release\netsody.exe"
	File "..\target\release\netsody-ui.exe"
	File ".\resources\app-icon.ico"

	CreateDirectory "$COMMONPROGRAMDATA\Netsody"

	CreateShortCut "$SMPROGRAMS\Netsody UI.lnk" "$INSTDIR\netsody-ui.exe" "" "$INSTDIR\app-icon.ico"

	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "DisplayName" "Netsody  - secure, software-defined overlay networks, connecting all your devices"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "UninstallString" "$\"$INSTDIR\netsody uninstaller.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "InstallLocation" "$\"$INSTDIR$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "HelpLink" "https://netsody.io"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "URLUpdateInfo" "https://netsody.io"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "URLInfoAbout" "https://netsody.io"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "DisplayIcon" "$\"$INSTDIR\app-icon.ico$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "Publisher" "Heiko Bornholdt & Kevin Roebert"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "DisplayVersion" "0.1.0"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "NoModify" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody" "NoRepair" 1

	DetailPrint "Creating Netsody service..."
	ExecWait 'sc create netsody binpath= "\"$INSTDIR\netsody.exe\" run-service --log-file $COMMONPROGRAMDATA\Netsody\netsody.log --log-level trace --config $COMMONPROGRAMDATA\Netsody\config.toml --token $COMMONPROGRAMDATA\Netsody\auth.token" DisplayName= "Netsody" start= auto'
	DetailPrint "Setting Netsody service description..."
	ExecWait 'sc description netsody "Netsody provides secure, software-defined overlay networks, connecting all your devices."'
	DetailPrint "Starting Netsody service..."
	ExecWait 'sc start netsody'

SectionEnd

Section "Uninstall"
	DetailPrint "Stopping Netsody service..."
    ExecWait 'sc stop netsody'
    DetailPrint "Deleting Netsody service..."
    ExecWait 'sc delete netsody'

	DetailPrint "Waiting for Netsody service to stop..."
	Sleep 5000

	DetailPrint "Terminating Netsody UI process..."
	ExecWait `taskkill /im netsody-ui.exe /f`

	DetailPrint "Terminating Netsody process..."
	ExecWait `taskkill /im netsody.exe /f`

	Delete "$SMPROGRAMS\Netsody UI.lnk"
    Delete "$INSTDIR\app-icon.ico"
    Delete "$INSTDIR\netsody-ui.exe"
    Delete "$INSTDIR\netsody.exe"
    Delete "$INSTDIR\wintun.dll"
    Delete "$INSTDIR\netsody uninstaller.exe"
    RMDir "$INSTDIR"

	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\netsody"

    ; Delete "$COMMONPROGRAMDATA\Netsody\netsody.log"
    ; Delete "$COMMONPROGRAMDATA\Netsody\config.toml"
    ; Delete "$COMMONPROGRAMDATA\Netsody\auth.token"
    ; RMDir "$COMMONPROGRAMDATA\Netsody"
SectionEnd