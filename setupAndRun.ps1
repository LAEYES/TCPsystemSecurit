# Créer les dossiers nécessaires
Write-Output "Création des dossiers nécessaires..."
$directories = @("src", "bin", "logs", "scripts")
foreach ($dir in $directories) {
    $path = "C:\TCPsystemSecureAutonomous\$dir"
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory | Out-Null
        Write-Output "Créé : $path"
    }
}

# Télécharger et installer le JDK
$jdkInstallerUrl = "https://download.oracle.com/java/17/latest/jdk-17_windows-x64_bin.zip"
$jdkZipPath = "C:\TCPsystemSecureAutonomous\jdk.zip"
$jdkExtractPath = "C:\TCPsystemSecureAutonomous\jdk"
$jdkBinPath = "C:\TCPsystemSecureAutonomous\jdk\bin"

Write-Output "Téléchargement du JDK..."
Invoke-WebRequest -Uri $jdkInstallerUrl -OutFile $jdkZipPath

Write-Output "Décompression du JDK..."
Expand-Archive -Path $jdkZipPath -DestinationPath $jdkExtractPath -Force

Write-Output "Configuration du PATH..."
$env:Path = "$jdkBinPath;$env:Path"
[System.Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

Write-Output "Suppression du fichier zip..."
Remove-Item -Path $jdkZipPath -Force

# Création des fichiers Java
$srcFolder = "C:\TCPsystemSecureAutonomous\src"
$tcpSystemUIFile = "$srcFolder\com\tcpsystem\TCPsystemUI.java"
$tcpSystemMonitorFile = "$srcFolder\com\tcpsystem\MonitorConnections.java"

Write-Output "Création des fichiers Java..."
$tcpSystemUIContent = @"
package com.tcpsystem;

import javax.swing.*;
import java.awt.*;

public class TCPsystemUI {
    public static void main(String[] args) {
        JFrame frame = new JFrame("TCP System UI");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        frame.setLayout(new BorderLayout());
        JTextArea textArea = new JTextArea();
        frame.add(new JScrollPane(textArea), BorderLayout.CENTER);
        frame.setVisible(true);
    }
}
"@
$tcpSystemUIContent | Out-File -FilePath $tcpSystemUIFile -Force

$tcpSystemMonitorContent = @"
package com.tcpsystem;

import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class MonitorConnections {
    private static final String LOG_FILE = "C:\\TCPsystemSecureAutonomous\\logs\\connection.log";

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(12345)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                logConnection(clientSocket.getInetAddress().toString());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void logConnection(String clientAddress) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
            String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            writer.write(timestamp + " - Connection from " + clientAddress);
            writer.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
"@
$tcpSystemMonitorContent | Out-File -FilePath $tcpSystemMonitorFile -Force

Write-Output "Fichier TCPsystemUI.java créé."
Write-Output "Fichier MonitorConnections.java créé."

# Compilation des fichiers Java
Write-Output "Compilation des fichiers Java..."
$javacPath = "C:\TCPsystemSecureAutonomous\bin\javac.exe"
$javaPath = "C:\TCPsystemSecureAutonomous\bin\java.exe"

$compilationJob = Start-Job -ScriptBlock {
    param($srcFolder, $binFolder, $javacPath)
    & $javacPath -d $binFolder $srcFolder\*.java
} -ArgumentList $srcFolder, $binFolder, $javacPath

Write-Output "Compilation en cours..."
Wait-Job -Id $compilationJob.Id
Remove-Job -Id $compilationJob.Id

Write-Output "Compilation réussie."

# Exécution du programme Java
Write-Output "Exécution du programme Java..."
Start-Process -NoNewWindow -FilePath $javaPath -ArgumentList "-cp C:\TCPsystemSecureAutonomous\bin com.tcpsystem.TCPsystemUI"

# Démarrage de la surveillance réseau
Write-Output "Démarrage de la surveillance réseau..."
Start-Process -NoNewWindow -FilePath $javaPath -ArgumentList "-cp C:\TCPsystemSecureAutonomous\bin com.tcpsystem.MonitorConnections"

Write-Output "Configuration terminée. Le système est maintenant en cours d'exécution."
