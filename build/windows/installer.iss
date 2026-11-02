; SentinelProxy installer (Inno Setup 6).
; Build: ISCC.exe /DAppVersion=0.1.1 /DSourceDir=..\..\dist\SentinelProxy build\windows\installer.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\SentinelProxy"
#endif
#define AppName "SentinelProxy"
#define AppExe "SentinelProxy.exe"
#define AppURL "https://github.com/DestroyersTaken/SentinelProxy"
#define TaskName "SentinelProxy"

[Setup]
AppId={{8C2F6B71-3E5A-4D0B-9B6E-5A1F2C7D9E40}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=DestroyersTaken
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\..\dist
OutputBaseFilename={#AppName}-{#AppVersion}-setup
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=force
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "runasadmin"; Description: "Always run as &administrator (needed to capture every app automatically)"; GroupDescription: "Capture:"
Name: "autostart"; Description: "Start SentinelProxy when I &sign in (in the tray, as administrator, without a UAC prompt)"; GroupDescription: "Capture:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion uninsrestartdelete
Source: "{#SourceDir}\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion uninsrestartdelete
Source: "{#SourceDir}\WinDivert-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "Rule-based proxy routing for every app"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Windows' own "Run this program as an administrator" compatibility flag.
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: string; ValueName: "{app}\{#AppExe}"; ValueData: "~ RUNASADMIN"; Tasks: runasadmin; Flags: uninsdeletevalue

[Run]
; Sign-in task with highest privileges: starts elevated without a UAC prompt.
Filename: "{sys}\schtasks.exe"; Parameters: "/Create /F /TN ""{#TaskName}"" /TR ""\""{app}\{#AppExe}\"" --minimized"" /SC ONLOGON /RL HIGHEST"; Flags: runhidden; Tasks: autostart; StatusMsg: "Setting up start at sign-in..."
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden; RunOnceId: "StopApp"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""{#TaskName}"""; Flags: runhidden; RunOnceId: "DeleteTask"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=all program=""{app}\{#AppExe}"""; Flags: runhidden; RunOnceId: "DeleteFirewallRule"
Filename: "{sys}\sc.exe"; Parameters: "stop WinDivert"; Flags: runhidden; RunOnceId: "StopDriver"

[Code]
const
  WebView2Key = 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  WebView2UserKey = 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  WebView2URL = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703';

function HasWebView2: Boolean;
var
  V: String;
begin
  Result := (RegQueryStringValue(HKLM, WebView2Key, 'pv', V) and (V <> '') and (V <> '0.0.0.0')) or
            (RegQueryStringValue(HKCU, WebView2UserKey, 'pv', V) and (V <> '') and (V <> '0.0.0.0'));
end;

procedure StopRunningApp;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningApp;
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    { Remove a sign-in task left by an earlier install if it was unticked now. }
    if not WizardIsTaskSelected('autostart') then
      Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /F /TN "{#TaskName}"', '', SW_HIDE, ewWaitUntilTerminated, Code);
    { The window uses Microsoft Edge WebView2, preinstalled on current Windows. }
    if not HasWebView2 then
    begin
      WizardForm.StatusLabel.Caption := 'Installing the Microsoft Edge WebView2 runtime...';
      try
        DownloadTemporaryFile(WebView2URL, 'MicrosoftEdgeWebview2Setup.exe', '', nil);
        Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'), '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, Code);
      except
        MsgBox('The Microsoft Edge WebView2 runtime could not be downloaded. SentinelProxy needs it to show its window; install it from https://developer.microsoft.com/microsoft-edge/webview2/', mbInformation, MB_OK);
      end;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent then
  begin
    if MsgBox('Also delete your SentinelProxy profiles, rules and logs?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(ExpandConstant('{userappdata}\SentinelProxy'), True, True, True);
  end;
end;
