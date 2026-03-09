$srcDir = "Messenger\app\src\main\java"
$binDir = "bin"

if (!(Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir | Out-Null }

Write-Host "Compiling project..."
$javaFiles = @(Get-ChildItem -Path $srcDir -Recurse -Filter *.java | ForEach-Object { $_.FullName })
if ($javaFiles.Count -gt 0) {
    javac -d $binDir -cp $binDir $javaFiles
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Compilation failed!"
        exit 1
    }
}

Write-Host "Running MessengerFrame..."
java -cp $binDir routybor.otp.Messenger.MessengerFrame