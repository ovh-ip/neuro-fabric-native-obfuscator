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
        foreach ($leak in @("SecretLogic", "ClientMixin", "FakeMinecraftClient", "integerAndFloatEdgeCases", "HY2026", "onClientTick")) {
            if ($dllText.Contains($leak)) { throw "SECURITY LEAK: Found plaintext '$leak' inside DLL!" }
        }
        Write-Host "[SecurityCheck] 0 plaintext class/method/literal leaks in DLL!"

        Write-Host "`n=== Verifying JAR structure: natives/, .fucked, junk dirs & zero SecretLogic.class ==="
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zCheck = [System.IO.Compression.ZipFile]::OpenRead($ProtStrongJar)
        $entryNames = $zCheck.Entries | ForEach-Object { $_.FullName }
        $zCheck.Dispose()
        $hasNativesDll = ($entryNames | Where-Object { $_ -eq "natives/test-mod-strong.dll" }).Count -eq 1
        if (-not $hasNativesDll) { throw "Missing natives/test-mod-strong.dll inside JAR!" }
        if ($entryNames -contains "dev/hydro/testmod/SecretLogic.class") { throw "SecretLogic.class MUST be encrypted as .fucked, not .class!" }
        if ($entryNames -contains "dev/hydro/testmod/SecretLogic`$Vec3.class") { throw "SecretLogic`$Vec3.class MUST be encrypted as .fucked!" }
        $fuckedCount = ($entryNames | Where-Object { $_.EndsWith(".fucked") }).Count
        $junkClassCount = ($entryNames | Where-Object { $_.EndsWith(".class") -and $_ -notmatch "^(dev/hydro/testmod|dev/hydro/rt|org/spongepowered)" }).Count
        Write-Host "[JarAudit] natives/test-mod-strong.dll=OK | .fucked files=$fuckedCount | junk .class files=$junkClassCount | SecretLogic.class=ABSENT"

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
    }
    default {
        Build-Hydro
        & $Java -cp "$BuildOut;$Libs" dev.hydro.j2c.Main --help
    }
}
