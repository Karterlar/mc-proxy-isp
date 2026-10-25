; Never let the installer forcibly terminate an active proxy or recovery operation.
!macro customCheckAppRunning
  ${nsProcess::FindProcess} "${APP_EXECUTABLE_FILENAME}" $R0
  ${if} $R0 != 603
    MessageBox MB_OK|MB_ICONEXCLAMATION "Please disconnect MC Proxy, release its network lock if needed, and exit it from the tray before installing or uninstalling. No process was terminated." /SD IDOK
    SetErrorLevel 1602
    Quit
  ${endif}
!macroend

; electron-builder supports a destructive hidden switch even when its default
; deleteAppDataOnUninstall setting is false. Recovery data must stay independent.
!macro customUnInit
  ClearErrors
  ${GetParameters} $R0
  ${GetOptions} $R0 "--delete-app-data" $R1
  ${ifNot} ${errors}
    MessageBox MB_OK|MB_ICONEXCLAMATION "Deleting MC Proxy data during uninstall is disabled. Keep all recovery records and remove this option to continue." /SD IDOK
    SetErrorLevel 1602
    Quit
  ${endif}
!macroend

; Keep an independent repair entry beside retained user data after uninstall.
!macro customUnInstall
  ClearErrors
  CreateDirectory "$APPDATA\${PRODUCT_NAME}\recovery-tools"
  CopyFiles /SILENT "$INSTDIR\resources\offline-chain-test\*.*" "$APPDATA\${PRODUCT_NAME}\recovery-tools"
  ${if} ${errors}
    MessageBox MB_OK|MB_ICONEXCLAMATION "Independent recovery tools could not be preserved. Uninstall was cancelled; no recovery data was deleted." /SD IDOK
    SetErrorLevel 1602
    Quit
  ${endif}
!macroend
