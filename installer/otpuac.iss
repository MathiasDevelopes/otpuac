#ifndef AppVersion
#define AppVersion "1.0.0"
#endif

#ifndef ArtifactsDir
#define ArtifactsDir "..\target\x86_64-pc-windows-msvc\release"
#endif

[Setup]
AppId={{D9E5C968-A5AA-4F9F-92A5-1D4B116AF2B7}
AppName=OTPUAC
AppVersion={#AppVersion}
AppPublisher=OTPUAC
DefaultDirName={autopf}\OTPUAC
DefaultGroupName=OTPUAC
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=OTPUAC-Setup-{#AppVersion}-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=OTPUAC
UninstallDisplayIcon={app}\otpuac-admin.exe
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#ArtifactsDir}\otpuac-admin.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ArtifactsDir}\otpuac-service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ArtifactsDir}\otpuac-setup.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ArtifactsDir}\otpuac_provider_rs.dll"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\OTPUAC Enrollment"; Filename: "{app}\otpuac-admin.exe"; Parameters: "show-enrollment"
Name: "{group}\Uninstall OTPUAC"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\otpuac-setup.exe"; Parameters: "install-managed --account-name ""{code:GetManagedAccountName}"" --issuer ""{code:GetIssuer}"" --install-dir ""{app}"" --program-data ""{commonappdata}\OTPUAC"" --enrollment-file ""{tmp}\otpuac-enrollment.txt"""; StatusMsg: "Creating the OTPUAC managed administrator account and installing the service..."; Flags: runhidden waituntilterminated
Filename: "notepad.exe"; Parameters: """{tmp}\otpuac-enrollment.txt"""; StatusMsg: "Opening OTPUAC authenticator enrollment..."; Flags: waituntilterminated; Check: ShouldShowEnrollment

[UninstallRun]
Filename: "{app}\otpuac-setup.exe"; Parameters: "uninstall --install-dir ""{app}"" --program-data ""{commonappdata}\OTPUAC"" --remove-data --remove-created-account"; Flags: runhidden waituntilterminated; RunOnceId: "OTPUACCleanup"

[Code]
var
  ManagedAccountPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  ManagedAccountPage :=
    CreateInputQueryPage(
      wpSelectDir,
      'Managed administrator account',
      'Choose the local administrator account OTPUAC will manage.',
      'Setup will create this local account, generate a strong random password, add it to the local Administrators group, and store the password only in the DPAPI-protected OTPUAC vault.'
    );
  ManagedAccountPage.Add('Local account name:', False);
  ManagedAccountPage.Add('Authenticator issuer label:', False);
  ManagedAccountPage.Values[0] := 'OTPUACAdmin';
  ManagedAccountPage.Values[1] := 'OTPUAC';
end;

function IsInvalidAccountChar(Value: String): Boolean;
var
  I: Integer;
  C: Char;
begin
  Result := False;
  for I := 1 to Length(Value) do
  begin
    C := Value[I];
    if (C = '"') or (C = '/') or (C = '\') or (C = '[') or (C = ']') or
       (C = ':') or (C = ';') or (C = '|') or (C = '=') or (C = ',') or
       (C = '+') or (C = '*') or (C = '?') or (C = '<') or (C = '>') or
       (C = '@') then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  AccountName: String;
  Issuer: String;
begin
  Result := True;

  if CurPageID = ManagedAccountPage.ID then
  begin
    AccountName := ManagedAccountPage.Values[0];
    Issuer := ManagedAccountPage.Values[1];

    if (Trim(AccountName) <> AccountName) or (Length(AccountName) = 0) then
    begin
      MsgBox('Enter a local account name without leading or trailing spaces.', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    if (Length(AccountName) > 20) or IsInvalidAccountChar(AccountName) then
    begin
      MsgBox('The local account name is not valid for Windows.', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    if Length(Trim(Issuer)) = 0 then
    begin
      MsgBox('Enter an authenticator issuer label.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;
end;

function GetManagedAccountName(Param: String): String;
begin
  Result := ManagedAccountPage.Values[0];
end;

function GetIssuer(Param: String): String;
begin
  Result := ManagedAccountPage.Values[1];
end;

function ShouldShowEnrollment: Boolean;
begin
  Result := not WizardSilent;
end;
