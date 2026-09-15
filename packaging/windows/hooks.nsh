; SPDX-License-Identifier: GPL-3.0-only
!include "LogicLib.nsh"
!include "x64.nsh"

!macro OCVPN_GUARD_RUN Action
  nsExec::ExecToStack '"$PLUGINSDIR\ocvpn-package-guard.exe" ${Action}'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "The install/state paths are not protected. Files are preserved; reconcile ownership before continuing."
    SetErrorLevel 1
    Abort
  ${EndIf}
!macroend

!macro OCVPN_MANAGER Command Registered
  nsExec::ExecToStack '"$INSTDIR\ocvpn-installer.exe" ${Command}'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "Native service management failed. Files are preserved. Run ocvpn service repair, then retry."
    SetErrorLevel 1
    Abort
  ${EndIf}
  ; ocvpn-installer uses serde_json::to_writer for this exact three-boolean
  ; Registration DTO. Accept both user-login states; never alter login here.
  ${If} $1 == '{"registered":${Registered},"approval_required":false,"login_registered":false}'
  ${ElseIf} $1 == '{"registered":${Registered},"approval_required":false,"login_registered":true}'
  ${Else}
    MessageBox MB_ICONSTOP|MB_OK "Native service registration or recovery is unresolved. The package operation is aborted before removing files."
    SetErrorLevel 1
    Abort
  ${EndIf}
!macroend

!macro OCVPN_PATH Action
  ${DisableX64FSRedirection}
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -File "$INSTDIR\resources\cli-path.ps1" ${Action}'
  Pop $0
  Pop $1
  ${EnableX64FSRedirection}
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "The optional machine PATH operation was denied. No execution policy was bypassed. Reconcile the PATH or retry without PATH registration."
    SetErrorLevel 1
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  SetRegView 64
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentBuildNumber"
  ${If} $0 < 19045
    MessageBox MB_ICONSTOP|MB_OK "Windows 10 22H2 or Windows 11 is required."
    SetErrorLevel 1
    Abort
  ${EndIf}
  ${If} $INSTDIR != "$PROGRAMFILES64\OpenConnect GUI"
    MessageBox MB_ICONSTOP|MB_OK "Install only in the machine Program Files\OpenConnect GUI directory."
    SetErrorLevel 1
    Abort
  ${EndIf}
  ; This guard comes from the installer itself, never from an unvalidated old
  ; installation. No PowerShell execution-policy change is needed to install.
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=ocvpn-package-guard.exe "${OCVPN_GUARD}"
  !insertmacro OCVPN_GUARD_RUN "prepare"
  SetOutPath "$INSTDIR"
  IfFileExists "$INSTDIR\ocvpn-installer.exe" ocvpn_prepare_old ocvpn_check_old
  ocvpn_prepare_old:
    !insertmacro OCVPN_MANAGER "uninstall" "false"
    Goto ocvpn_prepared
  ocvpn_check_old:
  IfFileExists "$INSTDIR\ocvpnd.exe" 0 ocvpn_prepared
    MessageBox MB_ICONSTOP|MB_OK "Existing service manager is missing. Repair the old installation before updating."
    SetErrorLevel 1
    Abort
  ocvpn_prepared:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro OCVPN_GUARD_RUN "protect"
  !insertmacro OCVPN_MANAGER "install" "true"
  ; Default No, including silent installs. Login registration is always user-side.
  IfSilent ocvpn_no_path
  MessageBox MB_YESNO|MB_DEFBUTTON2 "Add the OpenConnect CLI directory to the machine PATH? Takes effect after signing in again." IDNO ocvpn_no_path
  !insertmacro OCVPN_PATH "add"
  ocvpn_no_path:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro OCVPN_MANAGER "uninstall" "false"
  !insertmacro OCVPN_MANAGER "status" "false"
  ; Avoid requiring script execution when PATH was never opted into.
  ReadRegStr $0 HKLM "SOFTWARE\OpenConnectGUI\Package" "PathAdded"
  ${If} $0 == "$INSTDIR"
    !insertmacro OCVPN_PATH "remove"
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; User profiles, keyring entries and unrelated network state remain untouched.
!macroend
