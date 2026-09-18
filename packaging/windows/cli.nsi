; SPDX-License-Identifier: GPL-3.0-only
Unicode true
!include "MUI2.nsh"
!include "hooks.nsh"
Name "OpenConnect GUI"
OutFile "${OUTPUT}"
InstallDir "$PROGRAMFILES64\OpenConnect GUI"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
Section "OpenConnect CLI/TUI and native service"
  SetRegView 64
  !insertmacro OCVPN_PREINSTALL
  IfFileExists "$INSTDIR\uninstall.exe" 0 ocvpn_cli_fresh
    ExecWait '"$INSTDIR\uninstall.exe" /S _?=$INSTDIR' $0
    ${If} $0 != 0
      SetErrorLevel 1
      Abort
    ${EndIf}
  ocvpn_cli_fresh:
  !insertmacro OCVPN_GUARD_RUN "prepare"
  SetOutPath "$INSTDIR"
  File /r "${PAYLOAD}\*"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnect GUI" "DisplayName" "OpenConnect CLI"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnect GUI" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnect GUI" "UninstallString" '$"$INSTDIR\uninstall.exe$"'
  !insertmacro NSIS_HOOK_POSTINSTALL
SectionEnd
Section "Uninstall"
  SetRegView 64
  !insertmacro NSIS_HOOK_PREUNINSTALL
  ; Delete only the generated package file list, never a recursive install root.
  !include "${PAYLOAD}\remove-files.nsh"
  Delete "$INSTDIR\remove-files.nsh"
  Delete "$INSTDIR\payload-manifest.json"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnect GUI"
  !insertmacro NSIS_HOOK_POSTUNINSTALL
SectionEnd
