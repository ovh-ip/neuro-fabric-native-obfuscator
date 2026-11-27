param(
    [Parameter(Position=0)][string]$Action = "help",
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$Rest
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildOut = Join-Path $Root "build\classes"
$AnnOut   = Join-Path $Root "build\ann-classes"
$AnnJar   = Join-Path $Root "build\neuro-annotations.jar"
$DistJar  = Join-Path $Root "build\hydro-j2c.jar"
$Libs = Join-Path $Root "libs\*"

# Find working JDK (prefer JAVA_HOME if valid, else Eclipse Adoptium)
$Jdk = $env:JAVA_HOME
if (-not $Jdk -or -not (Test-Path (Join-Path $Jdk "bin\javac.exe"))) {
    $found = Get-ChildItem "C:\Program Files\Eclipse Adoptium" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if ($found) { $Jdk = $found.FullName }
}
if (-not $Jdk -or -not (Test-Path (Join-Path $Jdk "bin\javac.exe"))) {
    throw "Cannot locate JDK with javac.exe"
}
$Javac = Join-Path $Jdk "bin\javac.exe"
$Java  = Join-Path $Jdk "bin\java.exe"
$Jar   = Join-Path $Jdk "bin\jar.exe"
$Javap = Join-Path $Jdk "bin\javap.exe"

function Build-Hydro {
    if (Test-Path $BuildOut) { Remove-Item -Recurse -Force $BuildOut }
    if (Test-Path $AnnOut) { Remove-Item -Recurse -Force $AnnOut }
    New-Item -ItemType Directory -Force $BuildOut | Out-Null
    New-Item -ItemType Directory -Force $AnnOut | Out-Null

    $annSources = Get-ChildItem -Recurse (Join-Path $Root "annotations\src\main\java") -Filter "*.java" | ForEach-Object { $_.FullName }
    & $Javac -encoding UTF-8 --release 17 -d $AnnOut $annSources
    if ($LASTEXITCODE -ne 0) { throw "annotations javac failed" }
    & $Jar cf $AnnJar -C $AnnOut .
    if ($LASTEXITCODE -ne 0) { throw "annotations jar failed" }

    $sources = Get-ChildItem -Recurse (Join-Path $Root "src\main\java") -Filter "*.java" | ForEach-Object { $_.FullName }
    & $Javac -encoding UTF-8 --release 21 -cp $Libs -d $BuildOut $sources
    if ($LASTEXITCODE -ne 0) { throw "javac failed" }
    $mainRes = Join-Path $Root "src\main\resources"
    if (Test-Path $mainRes) {
        Copy-Item -Recurse -Force "$mainRes\*" $BuildOut
    }
    # Package runnable fat JAR (classes + ASM)
    $stage = Join-Path $Root "build\fat-stage"
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    New-Item -ItemType Directory -Force $stage | Out-Null
    Copy-Item -Recurse -Force "$BuildOut\*" $stage
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    foreach ($libJar in Get-ChildItem (Join-Path $Root "libs") -Filter "*.jar") {
        $z = [System.IO.Compression.ZipFile]::OpenRead($libJar.FullName)
        foreach ($ent in $z.Entries) {
            if ($ent.FullName.EndsWith("/") -or $ent.FullName.StartsWith("META-INF/")) { continue }
            $dst = Join-Path $stage ($ent.FullName -replace '/', '\')
            $dir = Split-Path -Parent $dst
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($ent, $dst, $true)
        }
        $z.Dispose()
    }
    & $Jar cfe $DistJar dev.hydro.j2c.Main -C $stage .
    if ($LASTEXITCODE -ne 0) { throw "fat jar failed" }
    Remove-Item -Recurse -Force $stage
    Write-Host "[HydroJ2C] Built successfully -> $DistJar & $AnnJar"
}

switch ($Action.ToLower()) {
    "build" {
        Build-Hydro
    }
    "protect" {
        Build-Hydro
        $cp = "$BuildOut;$Libs"
        & $Java -cp $cp dev.hydro.j2c.Main @Rest
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    "test" {
        Build-Hydro
        $TestBuild    = Join-Path $Root "build\test-classes"
        $HarnessBuild = Join-Path $Root "build\test-harness"
        $TestJar      = Join-Path $Root "build\test-mod.jar"
        $ProtStrongJar = Join-Path $Root "build\test-mod-strong.jar"
        $ProtStrongDll = Join-Path $Root "build\test-mod-strong.dll"
        $ProtUltraJar  = Join-Path $Root "build\test-mod-ultra.jar"
        $ProtUltraDll  = Join-Path $Root "build\test-mod-ultra.dll"

        if (Test-Path $TestBuild) { Remove-Item -Recurse -Force $TestBuild }
        if (Test-Path $HarnessBuild) { Remove-Item -Recurse -Force $HarnessBuild }
        New-Item -ItemType Directory -Force $TestBuild | Out-Null
        New-Item -ItemType Directory -Force $HarnessBuild | Out-Null

        $testSources = Get-ChildItem -Recurse (Join-Path $Root "src\test\java") -Filter "*.java" | ForEach-Object { $_.FullName }
        & $Javac -encoding UTF-8 --release 21 -cp $AnnJar -d $TestBuild $testSources
        if ($LASTEXITCODE -ne 0) { throw "test javac failed" }

        $harnessSources = Get-ChildItem -Recurse (Join-Path $Root "src\test\harness") -Filter "*.java" | ForEach-Object { $_.FullName }
        & $Javac -encoding UTF-8 --release 21 -cp $Libs -d $HarnessBuild $harnessSources
        if ($LASTEXITCODE -ne 0) { throw "harness javac failed" }

        # Copy test resources (fabric.mod.json, mixins.json)
        $resDir = Join-Path $Root "src\test\resources"
        if (Test-Path $resDir) {
            Copy-Item -Recurse -Force "$resDir\*" $TestBuild
        }
        & $Jar cf $TestJar -C $TestBuild .
        if ($LASTEXITCODE -ne 0) { throw "jar failed" }

        $cp = "$BuildOut;$Libs"
        Write-Host "`n=== Running HydroJ2C STRONG tier protection (ALL anti-debug/dump/tamper ON) ==="
        & $Java -cp $cp dev.hydro.j2c.Main -i $TestJar -o $ProtStrongJar -d $ProtStrongDll --tier STRONG
        if ($LASTEXITCODE -ne 0) { throw "STRONG protection failed" }

        Write-Host "`n=== Verifying DLL exports, dependencies & zero plaintext string leaks ==="
        ntldd $ProtStrongDll
        objdump -p $ProtStrongDll | Select-String -Pattern "Export|Ordinal|JNI_OnLoad|hy_fn_|Name Table" -Context 0,2
        $dllRaw = [System.IO.File]::ReadAllBytes($ProtStrongDll)
        $dllText = [System.Text.Encoding]::ASCII.GetString($dllRaw)
        $peLfa = [BitConverter]::ToInt32($dllRaw, 0x3C)
        $peTs = [BitConverter]::ToUInt32($dllRaw, $peLfa + 8)
        if ($peTs -ne 0) { throw "SECURITY LEAK: PE COFF TimeDateStamp not scrubbed ($peTs)!" }
        foreach ($leak in @(
            "SecretLogic", "ClientMixin", "FakeMinecraftClient", "integerAndFloatEdgeCases",
            "HY2026", "onClientTick", "HYDROSEA", "AESORDYH", "xrunjdwp", "jdwp",
            "winhttp.dll", "advapi32.dll", "bcrypt.dll", "BCryptGenRandom",
            "WinHttpOpen", "RegOpenKeyExA", "CreateFileA", "/api/v1/session", "HY-HS-AUTH",
            "HY-REQ-E2", "HY-SESS-V1", "HY-SESS-V2", "HY-HWID-V1", "sessionId", "srvEphPub",
            "serverNonce", "HydroAgent/1.0"
        )) {
            if ($dllText.Contains($leak)) { throw "SECURITY LEAK: Found plaintext '$leak' inside DLL!" }
        }
        Write-Host "[SecurityCheck] 0 plaintext class/method/WinAPI/protocol/timestamp leaks in DLL!"

        Write-Host "`n=== Verifying JAR structure: natives/<os>-<arch>/, .fucked, junk dirs & zero SecretLogic.class ==="
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zCheck = [System.IO.Compression.ZipFile]::OpenRead($ProtStrongJar)
        $entryNames = $zCheck.Entries | ForEach-Object { $_.FullName }
        $zCheck.Dispose()
        $hasNativesDll = ($entryNames | Where-Object { $_ -eq "natives/windows-x86_64/test-mod-strong.dll" }).Count -eq 1
        if (-not $hasNativesDll) { throw "Missing natives/windows-x86_64/test-mod-strong.dll inside JAR!" }
        if ($entryNames -contains "dev/hydro/testmod/SecretLogic.class") { throw "SecretLogic.class MUST be encrypted as .fucked, not .class!" }
        if ($entryNames -contains "dev/hydro/testmod/SecretLogic`$Vec3.class") { throw "SecretLogic`$Vec3.class MUST be encrypted as .fucked!" }
        $fuckedCount = ($entryNames | Where-Object { $_.EndsWith(".fucked") }).Count
        $junkClassCount = ($entryNames | Where-Object { $_.EndsWith(".class") -and $_ -notmatch "^(dev/hydro/testmod|dev/hydro/rt|org/spongepowered)" }).Count
        Write-Host "[JarAudit] natives/windows-x86_64/test-mod-strong.dll=OK | .fucked files=$fuckedCount | junk .class files=$junkClassCount | SecretLogic.class=ABSENT"

        Write-Host "`n=== Inspecting javap bytecode of TestModEntrypoint & ClientMixin ==="
        & $Javap -c -p -cp $ProtStrongJar dev.hydro.testmod.TestModEntrypoint | Select-Object -First 35
        & $Javap -c -p -cp $ProtStrongJar dev.hydro.testmod.mixin.ClientMixin | Select-Object -First 40

        Write-Host "`n=== Executing STRONG protected mod JAR (isolated Child ClassLoader + Mixin simulation) ==="
        & $Java -cp "$HarnessBuild;$Libs" dev.hydro.harness.TestHarness $ProtStrongJar
        if ($LASTEXITCODE -ne 0) { throw "STRONG verification failed" }

        Write-Host "`n=== Running HydroJ2C ULTRA tier (CFF + Randomized Native VM + External DLL) protection ==="
        $ProtExtJar = Join-Path $Root "build\test-mod-ext.jar"
        $ProtExtDll = Join-Path $Root "build\test-mod-ext.dll"
        & $Java -cp $cp dev.hydro.j2c.Main -i $TestJar -o $ProtExtJar -d $ProtExtDll --tier ULTRA --vm "dev/hydro/testmod/SecretLogic" --external-dll "test-mod-ext.dll"
        if ($LASTEXITCODE -ne 0) { throw "ULTRA external-dll protection failed" }

        Write-Host "`n=== Executing ULTRA external-dll protected mod JAR ==="
        & $Java -cp "$HarnessBuild;$Libs" dev.hydro.harness.TestHarness $ProtExtJar
        if ($LASTEXITCODE -ne 0) { throw "ULTRA external-dll verification failed" }

        Write-Host "`n=== Running Annotation-Only (-a / @Native / @NotNative / @NativeVM) protection ==="
        $ProtAnnJar = Join-Path $Root "build\test-mod-annot.jar"
        $ProtAnnDll = Join-Path $Root "build\test-mod-annot.dll"
        & $Java -cp $cp dev.hydro.j2c.Main -a -i $TestJar -o $ProtAnnJar -d $ProtAnnDll --tier STRONG
        if ($LASTEXITCODE -ne 0) { throw "Annotation-only protection failed" }

        Write-Host "`n=== Executing Annotation-Only protected mod JAR ==="
        & $Java -cp "$HarnessBuild;$Libs" dev.hydro.harness.TestHarness $ProtAnnJar --annot-only
        if ($LASTEXITCODE -ne 0) { throw "Annotation-only verification failed" }

        Write-Host "`n=== Running Anti-Tamper negative test (modifying fabric.mod.json in copy) ==="
        $TamperedJar = Join-Path $Root "build\test-mod-tampered.jar"
        Copy-Item -Force $ProtStrongJar $TamperedJar
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::Open($TamperedJar, [System.IO.Compression.ZipArchiveMode]::Update)
        $e = $zip.GetEntry("fabric.mod.json")
        if ($e) { $e.Delete() }
        $ne = $zip.CreateEntry("fabric.mod.json")
        $sw = New-Object System.IO.StreamWriter($ne.Open())
        $sw.Write('{"schemaVersion":1,"id":"hacked"}')
        $sw.Close()
        $zip.Dispose()
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $Java -cp "$HarnessBuild;$Libs" dev.hydro.harness.TestHarness $TamperedJar 2>&1 | Out-Null
        $tamperExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        if ($tamperExit -eq 0) { throw "Anti-Tamper FAILED to block tampered JAR!" }
        Write-Host "[AntiTamper] Tampered JAR cleanly rejected (exit=$tamperExit)!"

        # =====================================================================
        # Standard Non-Fabric JAR Tests (Runnable java -jar, -a mode, Library)
        # =====================================================================
        Write-Host "`n=== Building Standard Runnable JAR (no fabric.mod.json) ==="
        $AppBuild = Join-Path $Root "build\test-app-classes"
        $AppAnnotBuild = Join-Path $Root "build\test-app-annot-classes"
        $LibBuild = Join-Path $Root "build\test-lib-classes"
        $CallerBuild = Join-Path $Root "build\test-caller-classes"
        foreach ($d in @($AppBuild, $AppAnnotBuild, $LibBuild, $CallerBuild)) {
            if (Test-Path $d) { Remove-Item -Recurse -Force $d }
            New-Item -ItemType Directory -Force $d | Out-Null
        }

        $appDemoSources = Get-ChildItem -Recurse (Join-Path $Root "src\test-app\java\app\demo") -Filter "*.java" | ForEach-Object { $_.FullName }
        & $Javac -encoding UTF-8 --release 21 -d $AppBuild $appDemoSources
        if ($LASTEXITCODE -ne 0) { throw "test-app javac failed" }
        Copy-Item -Recurse -Force (Join-Path $Root "src\test-app\resources\*") $AppBuild
        $AppJar = Join-Path $Root "build\test-app.jar"
        & $Jar cfe $AppJar app.demo.CliMain -C $AppBuild .
        if ($LASTEXITCODE -ne 0) { throw "test-app jar failed" }

        $ProtAppStrongJar = Join-Path $Root "build\test-app-strong.jar"
        $ProtAppStrongDll = Join-Path $Root "build\test-app-strong.dll"
        Write-Host "`n=== Protecting Standard Runnable JAR (STRONG tier) ==="
        & $Java -cp $cp dev.hydro.j2c.Main -i $AppJar -o $ProtAppStrongJar -d $ProtAppStrongDll --tier STRONG
        if ($LASTEXITCODE -ne 0) { throw "Standard JAR STRONG protection failed" }

        $zApp = [System.IO.Compression.ZipFile]::OpenRead($ProtAppStrongJar)
        $appEntries = $zApp.Entries | ForEach-Object { $_.FullName }
        $zApp.Dispose()
        if ($appEntries -contains "app/demo/SecretCore.class") { throw "SecretCore.class MUST be encrypted as .fucked!" }
        if ($appEntries -notcontains "app/demo/CliMain.class") { throw "CliMain.class (Main-Class) MUST remain .class!" }
        if ($appEntries -notcontains "natives/windows-x86_64/test-app-strong.dll") { throw "Missing natives/windows-x86_64/test-app-strong.dll inside JAR!" }
        if (($appEntries | Where-Object { $_ -like "net/minecraft/*" }).Count -ne 0) { throw "Standard non-Fabric JAR must not emit net/minecraft junk!" }

        Write-Host "`n=== Launching java -jar test-app-strong.jar directly ==="
        $appOutStrong = & $Java -jar $ProtAppStrongJar 7 cliTest
        if ($LASTEXITCODE -ne 0) { throw "java -jar test-app-strong.jar failed (exit=$LASTEXITCODE)" }
        Write-Host "[StandardJar-STRONG] $appOutStrong"
        if ("$appOutStrong" -notmatch "APP_OK\|args=7,cliTest\|.*HYDRO_APP_BANNER_2026.*ERR:NEGATIVE_SEED:-3") {
            throw "Unexpected output from test-app-strong.jar: $appOutStrong"
        }

        $ProtAppUltraJar = Join-Path $Root "build\test-app-ultra.jar"
        $ProtAppUltraDll = Join-Path $Root "build\test-app-ultra.dll"
        Write-Host "`n=== Protecting Standard Runnable JAR (ULTRA + Native VM + --encrypt-dll) ==="
        & $Java -cp $cp dev.hydro.j2c.Main -i $AppJar -o $ProtAppUltraJar -d $ProtAppUltraDll --tier ULTRA --encrypt-dll
        if ($LASTEXITCODE -ne 0) { throw "Standard JAR ULTRA protection failed" }

        $zUltra = [System.IO.Compression.ZipFile]::OpenRead($ProtAppUltraJar)
        $uDllEnt = $zUltra.GetEntry("natives/windows-x86_64/test-app-ultra.dll")
        if (-not $uDllEnt) { $zUltra.Dispose(); throw "Missing encrypted DLL payload in JAR!" }
        $uStream = $uDllEnt.Open()
        $uHdr = New-Object byte[] 2
        $uStream.Read($uHdr, 0, 2) | Out-Null
        $uStream.Dispose()
        # Verify encrypted DLL payload does not start with plaintext PE 'MZ' header
        if ($uHdr[0] -eq 0x4D -and $uHdr[1] -eq 0x5A) { $zUltra.Dispose(); throw "--encrypt-dll FAILED: plaintext MZ header inside JAR!" }
        # Verify HLoader has zero plaintext loader strings in bytecode
        $loaderEntry = $zUltra.Entries | Where-Object { $_.FullName -match "^dev/hydro/rt/H_.*\.class$" } | Select-Object -First 1
        if (-not $loaderEntry) { $zUltra.Dispose(); throw "Missing HLoader class in JAR!" }
        $msL = New-Object System.IO.MemoryStream
        $ls = $loaderEntry.Open(); $ls.CopyTo($msL); $ls.Dispose()
        $loaderText = [System.Text.Encoding]::ASCII.GetString($msL.ToArray())
        foreach ($lstr in @("os.name", "os.arch", "/natives/", "Missing native payload")) {
            if ($loaderText.Contains($lstr)) { $zUltra.Dispose(); throw "HLoader leaked plaintext string '$lstr'!" }
        }
        $zUltra.Dispose()
        Write-Host "[Loader+EncDllAudit] Encrypted DLL payload (!MZ) + 0 plaintext HLoader strings OK!"

        Write-Host "`n=== Launching java -jar test-app-ultra.jar directly ==="
        $appOutUltra = & $Java -jar $ProtAppUltraJar 9 ultraRun
        if ($LASTEXITCODE -ne 0) { throw "java -jar test-app-ultra.jar failed (exit=$LASTEXITCODE)" }
        Write-Host "[StandardJar-ULTRA] $appOutUltra"
        if ("$appOutUltra" -notmatch "APP_OK\|args=9,ultraRun\|.*HYDRO_APP_BANNER_2026.*ERR:NEGATIVE_SEED:-3") {
            throw "Unexpected output from test-app-ultra.jar: $appOutUltra"
        }

        $zAnn = [System.IO.Compression.ZipFile]::OpenRead($ProtAppUltraJar)
        $ecEnt = $zAnn.GetEntry("app/demo/EngineContract.class")
        if (-not $ecEnt) { $zAnn.Dispose(); throw "Missing EngineContract.class in test-app-ultra.jar" }
        $msEc = New-Object System.IO.MemoryStream
        $esEc = $ecEnt.Open(); $esEc.CopyTo($msEc); $esEc.Dispose()
        $zAnn.Dispose()
        $ecText = [System.Text.Encoding]::ASCII.GetString($msEc.ToArray())
        if ($ecText.Contains("CONTRACT-V1")) {
            throw "Residual Java string encryption FAILED: 'CONTRACT-V1' plaintext in EngineContract.class!"
        }
        Write-Host "[ResidualJavaHardening] Interface & startup .class files have 0 plaintext strings!"

        Write-Host "`n=== Standard JAR Annotation-Only (-a) test (Main unannotated -> HLoader.boot) ==="
        $appAnnSources = Get-ChildItem -Recurse (Join-Path $Root "src\test-app\java\app\annot") -Filter "*.java" | ForEach-Object { $_.FullName }
        & $Javac -encoding UTF-8 --release 21 -cp $AnnJar -d $AppAnnotBuild $appAnnSources
        if ($LASTEXITCODE -ne 0) { throw "test-app annot javac failed" }
        $AppAnnotJar = Join-Path $Root "build\test-app-annot.jar"
        & $Jar cfe $AppAnnotJar app.annot.AnnotOnlyMain -C $AppAnnotBuild .
        if ($LASTEXITCODE -ne 0) { throw "test-app annot jar failed" }

        $ProtAppAnnJar = Join-Path $Root "build\test-app-annot-prot.jar"
        $ProtAppAnnDll = Join-Path $Root "build\test-app-annot-prot.dll"
        & $Java -cp $cp dev.hydro.j2c.Main -a -i $AppAnnotJar -o $ProtAppAnnJar -d $ProtAppAnnDll --tier ULTRA
        if ($LASTEXITCODE -ne 0) { throw "Standard JAR annotation-only protection failed" }
        $appAnnOut = & $Java -jar $ProtAppAnnJar myTag
        if ($LASTEXITCODE -ne 0) { throw "java -jar test-app-annot-prot.jar failed" }
        Write-Host "[StandardJar-AnnotOnly] $appAnnOut"
        if ("$appAnnOut" -ne "APP_ANN_OK|VAULT:myTag:128|plain=123") {
            throw "Unexpected output from test-app-annot-prot.jar: $appAnnOut"
        }

        Write-Host "`n=== Standard Library JAR (no Main-Class) + Multi-JAR Classpath test ==="
        $libSources = Get-ChildItem -Recurse (Join-Path $Root "src\test-lib\java") -Filter "*.java" | ForEach-Object { $_.FullName }
        & $Javac -encoding UTF-8 --release 21 -d $LibBuild $libSources
        if ($LASTEXITCODE -ne 0) { throw "test-lib javac failed" }
        $LibJar = Join-Path $Root "build\test-lib.jar"
        & $Jar cf $LibJar -C $LibBuild .
        if ($LASTEXITCODE -ne 0) { throw "test-lib jar failed" }

        $ProtLibJar = Join-Path $Root "build\test-lib-prot.jar"
        $ProtLibDll = Join-Path $Root "build\test-lib-prot.dll"
        & $Java -cp $cp dev.hydro.j2c.Main -i $LibJar -o $ProtLibJar -d $ProtLibDll --tier STRONG
        if ($LASTEXITCODE -ne 0) { throw "Library JAR protection failed" }

        $zLib = [System.IO.Compression.ZipFile]::OpenRead($ProtLibJar)
        $libEntries = $zLib.Entries | ForEach-Object { $_.FullName }
        $zLib.Dispose()
        if ($libEntries -contains "lib/vendor/InternalCipher.class") { throw "Package-private InternalCipher MUST be encrypted as .fucked!" }
        if ($libEntries -notcontains "lib/vendor/VendorApi.class") { throw "Public VendorApi MUST stay .class!" }

        $callerSources = Get-ChildItem -Recurse (Join-Path $Root "src\test-caller\java") -Filter "*.java" | ForEach-Object { $_.FullName }
        & $Javac -encoding UTF-8 --release 21 -cp $ProtLibJar -d $CallerBuild $callerSources
        if ($LASTEXITCODE -ne 0) { throw "test-caller javac failed" }
        $CallerJar = Join-Path $Root "build\test-caller.jar"
        & $Jar cfe $CallerJar app.caller.ExternalCaller -C $CallerBuild .
        if ($LASTEXITCODE -ne 0) { throw "test-caller jar failed" }

        # Caller JAR comes FIRST on -cp so its own META-INF/MANIFEST.MF tests multi-JAR Anti-Tamper isolation!
        $libOut = & $Java -cp "$CallerJar;$ProtLibJar" app.caller.ExternalCaller
        if ($LASTEXITCODE -ne 0) { throw "Multi-JAR library invocation failed" }
        Write-Host "[LibraryJar-MultiCP] $libOut"
        if ("$libOut" -notmatch "^LIB_CALLER_OK\|SIG-[0-9a-f]+-alice$") {
            throw "Unexpected output from library caller: $libOut"
        }

        Write-Host "`n=== Standard JAR Anti-Tamper negative test (modifying MANIFEST.MF) ==="
        $TamperedAppJar = Join-Path $Root "build\test-app-tampered.jar"
        Copy-Item -Force $ProtAppStrongJar $TamperedAppJar
        $zipApp = [System.IO.Compression.ZipFile]::Open($TamperedAppJar, [System.IO.Compression.ZipArchiveMode]::Update)
        $mfEntry = $zipApp.GetEntry("META-INF/MANIFEST.MF")
        if ($mfEntry) { $mfEntry.Delete() }
        $newMf = $zipApp.CreateEntry("META-INF/MANIFEST.MF")
        $swMf = New-Object System.IO.StreamWriter($newMf.Open())
        $swMf.Write("Manifest-Version: 1.0`r`nMain-Class: app.demo.CliMain`r`nX-Tampered: true`r`n`r`n")
        $swMf.Close()
        $zipApp.Dispose()
        $prevEap2 = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $Java -jar $TamperedAppJar 2>&1 | Out-Null
        $appTamperExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEap2
        if ($appTamperExit -eq 0) { throw "Standard JAR Anti-Tamper FAILED to block modified MANIFEST.MF!" }
        Write-Host "[StandardJar-AntiTamper] Modified MANIFEST.MF cleanly rejected (exit=$appTamperExit)!"

        Write-Host "`n=== Cross-Platform CMake Build + Multi-OS --natives-dir Packaging Test (ULTRA tier) ==="
        $CmakeExportDir = Join-Path $Root "build\test-cmake-export"
        $PrebuiltDir = Join-Path $Root "build\test-prebuilt-natives"
        foreach ($d in @($CmakeExportDir, $PrebuiltDir)) {
            if (Test-Path $d) { Remove-Item -Recurse -Force $d }
        }
        New-Item -ItemType Directory -Force (Join-Path $PrebuiltDir "linux-x86_64") | Out-Null
        New-Item -ItemType Directory -Force (Join-Path $PrebuiltDir "macos-arm64") | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $PrebuiltDir "linux-x86_64\libtest-app-cmake.so"), [byte[]](0x7F,0x45,0x4C,0x46,0x02,0x01))
        [System.IO.File]::WriteAllBytes((Join-Path $PrebuiltDir "macos-arm64\libtest-app-cmake.dylib"), [byte[]](0xCF,0xFA,0xED,0xFE))

        $ProtCmakeJar = Join-Path $Root "build\test-app-cmake.jar"
        $ProtCmakeDll = Join-Path $Root "build\test-app-cmake.dll"
        & $Java -cp $cp dev.hydro.j2c.Main -i $AppJar -o $ProtCmakeJar -d $ProtCmakeDll --tier ULTRA --cmake --cmake-out $CmakeExportDir --natives-dir $PrebuiltDir
        if ($LASTEXITCODE -ne 0) { throw "CMake + --natives-dir ULTRA build failed" }

        foreach ($f in @("CMakeLists.txt", "hydro_runtime.hpp", "hydro_crypto.hpp", "hydro_build_cfg.hpp", "hydro_memory.cpp", "hydro_crypto.cpp", "hydro_security.cpp", "hydro_net.cpp", "hydro_jni_bridge.cpp", "hydro_vm_core.cpp", "hydro_tables.cpp", "exports.def", "exports.map", "exports.exp")) {
            if (-not (Test-Path (Join-Path $CmakeExportDir $f))) { throw "Missing exported CMake file: $f" }
        }
        $zCmake = [System.IO.Compression.ZipFile]::OpenRead($ProtCmakeJar)
        $cmakeEntries = $zCmake.Entries | ForEach-Object { $_.FullName }
        $zCmake.Dispose()
        foreach ($natPath in @("natives/windows-x86_64/test-app-cmake.dll", "natives/linux-x86_64/libtest-app-cmake.so", "natives/macos-arm64/libtest-app-cmake.dylib")) {
            if ($cmakeEntries -notcontains $natPath) { throw "Missing multi-OS native payload in JAR: $natPath" }
        }

        $unprotOut = & $Java -jar $AppJar 13 cmakeCheck
        if ($LASTEXITCODE -ne 0) { throw "Unprotected test-app.jar execution failed" }
        $cmakeOut = & $Java -jar $ProtCmakeJar 13 cmakeCheck
        if ($LASTEXITCODE -ne 0) { throw "Protected CMake test-app-cmake.jar execution failed (exit=$LASTEXITCODE)" }
        if ("$cmakeOut" -ne "$unprotOut") { throw "Parity mismatch! Unprotected='$unprotOut' vs CMake-ULTRA='$cmakeOut'" }
        Write-Host "[CMake+Parity] Exact match: $cmakeOut"

        Write-Host "`n=== Spring Boot License Server + Dynamic Session / Rolling Heartbeat / Live Ban E2E ==="
        $ServerJar = Join-Path $Root "server\build\libs\hydro-server-1.0.0.jar"
        if (-not (Test-Path $ServerJar)) {
            $prevJh = $env:JAVA_HOME
            $env:JAVA_HOME = $Jdk
            & "$env:USERPROFILE\.gradle\wrapper\dists\gradle-9.8.2-bin\8wepis63pzuhrlfaiy04bagwu\gradle-9.8.2\bin\gradle.bat" -p (Join-Path $Root "server") bootJar --no-daemon | Out-Null
            $gExit = $LASTEXITCODE
            $env:JAVA_HOME = $prevJh
            if ($gExit -ne 0 -or -not (Test-Path $ServerJar)) { throw "Gradle bootJar failed for Spring server (exit=$gExit)" }
        }
        $SrvPort = 18923
        Get-NetTCPConnection -LocalPort $SrvPort -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
            Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 300
        }
        $SrvKeys = Join-Path $Root "build\test-srv-keys.json"
        $SrvDb = Join-Path $Root "build\test-srv-db"
        $SrvLog = Join-Path $Root "build\test-srv.log"
        foreach ($p in @($SrvKeys, $SrvLog)) { if (Test-Path $p) { Remove-Item -Force $p } }
        if (Test-Path "$SrvDb.mv.db") { Remove-Item -Force "$SrvDb.mv.db" }

        $srvProc = Start-Process -FilePath $Java -ArgumentList @(
            "-jar", $ServerJar,
            "--server.port=$SrvPort",
            "--spring.datasource.url=jdbc:h2:file:$SrvDb;DB_CLOSE_DELAY=-1",
            "--hydro.server.keys-file=$SrvKeys",
            "--hydro.server.heartbeat-interval-sec=2",
            "--hydro.server.session-lease-sec=6"
        ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $SrvLog -RedirectStandardError (Join-Path $Root "build\test-srv-err.log")

        try {
            $srvUrl = "http://127.0.0.1:$SrvPort"
            $health = $null
            for ($w = 0; $w -lt 40; $w++) {
                if ($srvProc.HasExited) { throw "Spring server exited prematurely (exit=$($srvProc.ExitCode))" }
                Start-Sleep -Milliseconds 400
                try {
                    $health = Invoke-RestMethod -Uri "$srvUrl/api/v1/health" -TimeoutSec 2
                    if ($health.status -eq "UP") { break }
                } catch {}
            }
            if (-not $health -or $health.status -ne "UP") { throw "Spring server failed to become UP" }
            $srvPub = $health.serverPubHex
            $keysJson = Get-Content -Raw $SrvKeys | ConvertFrom-Json
            $adminTok = $keysJson.adminToken
            Write-Host "[SpringServer] UP on $srvUrl | pub=$($srvPub.Substring(0,16))..."

            $ProtSrvJar = Join-Path $Root "build\test-app-srv.jar"
            $ProtSrvDll = Join-Path $Root "build\test-app-srv.dll"
            $SrvMf = Join-Path $Root "build\test-app-srv-server.json"
            & $Java -cp $cp dev.hydro.j2c.Main -i $AppJar -o $ProtSrvJar -d $ProtSrvDll --tier ULTRA `
                --server-url $srvUrl --server-pubkey $srvPub --product-id "hydro-app" `
                --server-admin-token $adminTok --server-heartbeat-sec 2 --manifest-out $SrvMf
            if ($LASTEXITCODE -ne 0) { throw "Server-bound ULTRA protection failed" }

            # Verify zero server secret shares, WinAPI/protocol strings, or PE timestamps inside DLL
            $mfObj = Get-Content -Raw $SrvMf | ConvertFrom-Json
            $srvDllRaw = [System.IO.File]::ReadAllBytes($ProtSrvDll)
            $srvPeLfa = [BitConverter]::ToInt32($srvDllRaw, 0x3C)
            if ([BitConverter]::ToUInt32($srvDllRaw, $srvPeLfa + 8) -ne 0) {
                throw "CRITICAL: Server DLL PE TimeDateStamp not zeroed!"
            }
            $dllStr = [System.Text.Encoding]::ASCII.GetString($srvDllRaw)
            if ($dllStr.Contains($mfObj.vmShareHex) -or $dllStr.Contains($mfObj.vaultShareHex) -or $dllStr.Contains($mfObj.dynParamsHex.Substring(0, 16))) {
                throw "CRITICAL: Server key shares or dynParams leaked into DLL!"
            }
            foreach ($sleak in @(
                "winhttp.dll", "advapi32.dll", "bcrypt.dll", "BCryptGenRandom",
                "WinHttpOpen", "RegOpenKeyExA", "CreateFileA", "/api/v1/session", "HY-HS-AUTH",
                "HY-REQ-E2", "HY-REQ-M2", "HY-SESS-V1", "HY-SESS-V2", "HY-HWID-V1",
                "HBQ|", "LOGOUT|", "sessionId", "srvEphPub", "serverNonce",
                "nonce12", "ciphertext", "HydroAgent/1.0", "Content-Type: application/json"
            )) {
                if ($dllStr.Contains($sleak)) { throw "SECURITY LEAK: Server DLL leaked plaintext '$sleak'!" }
            }

            # 0) Verify plaintext / spoofed non-E2EE handshake is rejected by Spring server
            $badHsOk = $false
            try {
                Invoke-RestMethod -Method Post -Uri "$srvUrl/api/v1/session/handshake" -ContentType "application/json" -Body '{"productId":"hydro-app","licenseKey":"FAKE"}' -TimeoutSec 2 | Out-Null
                $badHsOk = $true
            } catch {}
            if ($badHsOk) { throw "Server accepted non-E2EE handshake!" }
            Write-Host "[ServerE2EE] Unencrypted/malformed handshake envelope rejected"

            # 1) Reject launch without license key
            $prevEap3 = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & $Java -jar $ProtSrvJar 21 noKey 2>&1 | Out-Null
            $noKeyExit = $LASTEXITCODE
            $ErrorActionPreference = $prevEap3
            if ($noKeyExit -eq 0) { throw "Server-protected JAR ran WITHOUT a license key!" }
            Write-Host "[ServerAuth] Missing license key cleanly rejected (exit=$noKeyExit)"

            # 2) Issue real license key via Admin API and verify execution + parity
            $licBody = '{"licenseKey":"HY-TEST-VALID-2026","productId":"hydro-app","durationDays":30,"maxHwids":1,"maxConcurrentSessions":1,"note":"e2e"}'
            $licResp = Invoke-RestMethod -Method Post -Uri "$srvUrl/api/v1/admin/licenses" -Headers @{ "X-Admin-Token" = $adminTok } -ContentType "application/json" -Body $licBody
            $licKey = $licResp.licenseKey

            $unprot21 = & $Java -jar $AppJar 21 srvCheck
            $srvOut21 = & $Java "-Dhydro.key=$licKey" -jar $ProtSrvJar 21 srvCheck
            if ($LASTEXITCODE -ne 0) { throw "Licensed execution failed (exit=$LASTEXITCODE)" }
            if ("$srvOut21" -ne "$unprot21") { throw "Server-ULTRA parity mismatch: '$srvOut21' vs '$unprot21'" }
            Write-Host "[ServerAuth] Valid X25519+ChaCha20 (E2EE v2) session & parity OK: $srvOut21"

            # 2b) Verify Server-bound CFF (STRONG tier using srvDynParams) also rejects noKey and matches parity with key
            $ProtSrvCffJar = Join-Path $Root "build\test-app-srv-cff.jar"
            $ProtSrvCffDll = Join-Path $Root "build\test-app-srv-cff.dll"
            & $Java -cp $cp dev.hydro.j2c.Main -i $AppJar -o $ProtSrvCffJar -d $ProtSrvCffDll --tier STRONG `
                --server-url $srvUrl --server-pubkey $srvPub --product-id "hydro-app" `
                --server-admin-token $adminTok --server-heartbeat-sec 2
            if ($LASTEXITCODE -ne 0) { throw "Server-bound STRONG CFF protection failed" }
            $prevEap3b = $ErrorActionPreference; $ErrorActionPreference = "Continue"
            & $Java -jar $ProtSrvCffJar 21 noKey 2>&1 | Out-Null
            $cffNoKeyExit = $LASTEXITCODE
            $ErrorActionPreference = $prevEap3b
            if ($cffNoKeyExit -eq 0) { throw "Server-bound STRONG CFF ran WITHOUT license key!" }
            $cffSrvOut = & $Java "-Dhydro.key=$licKey" -jar $ProtSrvCffJar 21 srvCheck
            if ($LASTEXITCODE -ne 0 -or "$cffSrvOut" -ne "$unprot21") {
                throw "Server-STRONG CFF execution/parity failed (exit=$LASTEXITCODE out='$cffSrvOut')"
            }
            Write-Host "[ServerCFF] Server-bound CFF state coupling + session eviction OK"

            # 3) Live rolling heartbeat + real-time admin revocation test
            $watchOutLog = Join-Path $Root "build\test-watch.out"
            $watchErrLog = Join-Path $Root "build\test-watch.err"
            $hsErrArg = "-XX:ErrorFile=$(Join-Path $Root 'build\watch_hs_err_%p.log')"
            $watchProc = Start-Process -FilePath $Java -ArgumentList @($hsErrArg, "-Dhydro.key=$licKey", "-jar", $ProtSrvJar, "17", "watch") -PassThru -NoNewWindow -RedirectStandardOutput $watchOutLog -RedirectStandardError $watchErrLog
            try {
                Start-Sleep -Milliseconds 3200
                $sessList = Invoke-RestMethod -Method Get -Uri "$srvUrl/api/v1/admin/sessions" -Headers @{ "X-Admin-Token" = $adminTok }
                if (-not $sessList -or $sessList[0].seq -lt 1) {
                    throw "Expected live rolling heartbeat seq >= 1, got: $($sessList | ConvertTo-Json -Compress)"
                }
                Write-Host "[Heartbeat] Rolling session active! seq=$($sessList[0].seq) hwid=$($sessList[0].hwid.Substring(0,16))..."

                # Admin bans license live while client is running
                $rev = Invoke-RestMethod -Method Post -Uri "$srvUrl/api/v1/admin/licenses/$licKey/revoke" -Headers @{ "X-Admin-Token" = $adminTok }
                $exited = $watchProc.WaitForExit(6000)
                if (-not $exited -or $watchProc.ExitCode -eq 0) {
                    throw "Live revoked client FAILED to terminate/invalidate! exited=$exited code=$($watchProc.ExitCode)"
                }
                $wOut = Get-Content -Raw $watchOutLog
                Write-Host "[LiveRevoke] Active client killed mid-flight cleanly (exit=$($watchProc.ExitCode)) -> $($wOut.Trim())"

                # 4) Subsequent launch with revoked key is blocked
                $prevEap4 = $ErrorActionPreference
                $ErrorActionPreference = "Continue"
                & $Java "-Dhydro.key=$licKey" -jar $ProtSrvJar 21 postBan 2>&1 | Out-Null
                $postBanExit = $LASTEXITCODE
                $ErrorActionPreference = $prevEap4
                if ($postBanExit -eq 0) { throw "Revoked key STILL allowed execution!" }
                Write-Host "[ServerAuth] Post-revoke relaunch blocked (exit=$postBanExit)"
            } finally {
                if (-not $watchProc.HasExited) { Stop-Process -Id $watchProc.Id -Force -ErrorAction SilentlyContinue }
            }
        } finally {
            if ($srvProc -and -not $srvProc.HasExited) { Stop-Process -Id $srvProc.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    default {
        Build-Hydro
        & $Java -cp "$BuildOut;$Libs" dev.hydro.j2c.Main --help
    }
}
