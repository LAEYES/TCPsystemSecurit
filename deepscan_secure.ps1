# Vérifier si le script est exécuté avec des privilèges administratifs
function Test-Admin {
    param (
        [string]$message = "Ce script nécessite des privilèges d'administrateur. Veuillez exécuter à nouveau en tant qu'administrateur."
    )
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error $message
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
        exit
    }
}

# Appeler la fonction pour tester les privilèges d'administrateur
Test-Admin

# Configuration
$logFile = "C:\log\securityLog.log"
$suspiciousIpsFile = "C:\log\suspiciousIps.txt"
$suspiciousFilesFile = "C:\log\suspiciousFiles.txt"
$alertEmail = "admin@example.com"
$smtpServer = "smtp.example.com"
$alertFrom = "alert@example.com"

# Créer les répertoires de journalisation s'ils n'existent pas
foreach ($path in @($logFile, $suspiciousIpsFile, $suspiciousFilesFile)) {
    $directory = Split-Path -Path $path -Parent
    if (-not (Test-Path -Path $directory)) {
        try {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        } catch {
            Write-Error "Échec de la création du répertoire ${directory}: $($_.Exception.Message). Veuillez vérifier les permissions."
        }
    }
}

# Fonction pour écrire dans le journal
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    try {
        Add-Content -Path $logFile -Value "${timestamp} - ${message}"
    } catch {
        Write-Error "Échec de l'écriture dans le journal: $($_.Exception.Message). Veuillez vérifier que le fichier est accessible."
    }
}

# Fonction pour envoyer un e-mail d'alerte
function Send-AlertEmail {
    param (
        [string]$subject,
        [string]$body
    )
    try {
        $emailMessage = New-Object system.net.mail.mailmessage
        $emailMessage.From = $alertFrom
        $emailMessage.To.Add($alertEmail)
        $emailMessage.Subject = $subject
        $emailMessage.Body = $body
        $smtp = New-Object Net.Mail.SmtpClient($smtpServer)
        $smtp.Send($emailMessage)
        Log-Message "E-mail d'alerte envoyé: ${subject}"
    } catch {
        Log-Message "Échec de l'envoi de l'e-mail d'alerte: $($_.Exception.Message). Vérifiez la configuration SMTP."
    }
}
function Audit-SecurityPolicies {
    $passwordPolicy = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge"
    Log-Message "Durée maximale de validité des mots de passe: $($passwordPolicy.MaximumPasswordAge)"
    
    $disabledAccounts = Get-LocalUser | Where-Object { $_.Enabled -eq $false }
    foreach ($account in $disabledAccounts) {
        Log-Message "Compte désactivé détecté: $($account.Name)"
    }
}

# Charger les IPs suspectes depuis le fichier
function Load-SuspiciousIps {
    if (Test-Path $suspiciousIpsFile) {
        return Get-Content -Path $suspiciousIpsFile
    }
    return @()
}

# Sauvegarder les IPs suspectes dans le fichier
function Save-SuspiciousIps {
    param (
        [string[]]$ips
    )
    try {
        $ips | Out-File -FilePath $suspiciousIpsFile -Encoding utf8 -Force
    } catch {
        Write-Error "Échec de la sauvegarde des IPs suspectes: $($_.Exception.Message). Vérifiez les permissions d'écriture sur le fichier."
    }
}

# Ajouter une IP à la liste et sauvegarder
function Add-SuspiciousIp {
    param (
        [string]$ipAddress
    )
    if ([System.Net.IPAddress]::TryParse($ipAddress, [ref]$null)) {
        $suspiciousIps = Load-SuspiciousIps
        if (-not ($suspiciousIps -contains $ipAddress)) {
            $suspiciousIps += $ipAddress
            Save-SuspiciousIps -ips $suspiciousIps
            Log-Message "IP suspecte ajoutée: ${ipAddress}"
            Send-AlertEmail -subject "Nouvelle IP suspecte ajoutée" -body "IP suspecte ajoutée: ${ipAddress}"
        }
    } else {
        Log-Message "Adresse IP invalide: ${ipAddress}. Veuillez fournir une adresse IP valide."
    }
}
function Monitor-FailedLogins {
    $failedLogins = Get-EventLog -LogName Security | Where-Object { $_.EventID -eq 4625 }
    foreach ($login in $failedLogins) {
        Log-Message "Tentative de connexion échouée détectée: $($login.ReplacementStrings[5]) sur $($login.TimeGenerated)"
        Send-AlertEmail -subject "Tentative de connexion échouée" -body "Tentative de connexion échouée par $($login.ReplacementStrings[5]) à $($login.TimeGenerated)"
    }
}

# Vérifier l'existence d'une règle de pare-feu
function Add-FirewallRuleIfNotExist {
    param (
        [string]$ipAddress
    )
    if (-not (Get-NetFirewallRule | Where-Object { $_.RemoteAddress -eq $ipAddress })) {
        try {
            Add-NetFirewallRule -DisplayName "Bloquer ${ipAddress}" -Direction Inbound -LocalPort All -Protocol TCP -RemoteAddress $ipAddress -Action Block
            Log-Message "Règle de pare-feu ajoutée pour IP: ${ipAddress}"
        } catch {
            Log-Message "Échec de l'ajout de la règle de pare-feu pour IP ${ipAddress}: $($_.Exception.Message). Assurez-vous que vous avez les droits administratifs."
        }
    } else {
        Log-Message "La règle de pare-feu existe déjà pour IP: ${ipAddress}"
    }
}
function Scan-WithWindowsDefender {
    param (
        [string]$filePath
    )
    
    try {
        Start-Process "MpCmdRun.exe" -ArgumentList "-Scan -ScanType 3 -File $filePath" -Wait -NoNewWindow
        Log-Message "Analyse Windows Defender effectuée sur le fichier: $filePath"
    } catch {
        Log-Message "Échec de l'analyse Windows Defender: $($_.Exception.Message)"
    }
}

# Fonction pour surveiller les connexions réseau
function Monitor-NetworkConnections {
    try {
        $connections = netstat -ano | Select-String -Pattern "ESTABLISHED"
        foreach ($connection in $connections) {
            $ipAddress = $connection -replace '.*(\d+\.\d+\.\d+\.\d+).*', '$1'
            if ($ipAddress) {
                Add-SuspiciousIp -ipAddress $ipAddress
                Add-FirewallRuleIfNotExist -ipAddress $ipAddress
            }
        }
    } catch {
        Log-Message "Erreur lors de la surveillance des connexions réseau: $($_.Exception.Message). Vérifiez si vous avez les droits d'exécution nécessaires."
    }
}
function Monitor-OpenPorts {
    $allowedPorts = @("80", "443", "22")
    $openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }

    foreach ($port in $openPorts) {
        if (-not ($allowedPorts -contains $port.LocalPort)) {
            Log-Message "Port non autorisé détecté: $($port.LocalPort) utilisé par $($port.OwningProcess)"
            Add-FirewallRuleIfNotExist -ipAddress $port.RemoteAddress
        }
    }
}

# Fonction pour surveiller les processus
function Monitor-Processes {
    try {
        $suspiciousProcesses = @("maliciousProcess.exe", "unwantedApp.exe")
        foreach ($proc in $suspiciousProcesses) {
            $runningProcesses = Get-Process -Name $proc -ErrorAction SilentlyContinue
            foreach ($process in $runningProcesses) {
                Log-Message "Processus suspect détecté: $($process.Name) avec PID $($process.Id)"
                Stop-Process -Id $process.Id -Force
                Send-AlertEmail -subject "Processus suspect arrêté" -body "Processus suspect arrêté: $($process.Name) avec PID $($process.Id)"
            }
        }
    } catch {
        Log-Message "Erreur lors de la surveillance des processus: $($_.Exception.Message). Vérifiez que vous avez les droits nécessaires."
    }
}

# Fonction pour désactiver les comptes d'utilisateur malveillants
function Disable-MaliciousUserAccounts {
    try {
        $suspiciousUsers = @("suspiciousUser", "maliciousUser")
        foreach ($user in $suspiciousUsers) {
            if (Get-LocalUser -Name $user -ErrorAction Stop) {
                Disable-LocalUser -Name $user
                Log-Message "Compte utilisateur désactivé: ${user}"
                Send-AlertEmail -subject "Compte utilisateur malveillant désactivé" -body "Compte utilisateur désactivé: ${user}"
            }
        }
    } catch {
        Log-Message "Erreur lors de la désactivation des comptes utilisateurs: $($_.Exception.Message). Assurez-vous que vous avez les droits d'administration."
    }
}

# Fonction pour renforcer les paramètres de sécurité
function Harden-SecuritySettings {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force
        Log-Message "Paramètres de sécurité renforcés: Politique d'exécution définie sur Restrictive"
    } catch {
        Log-Message "Échec du renforcement des paramètres de sécurité: $($_.Exception.Message). Vérifiez les droits d'accès ou la configuration du système."
    }
}
function Encrypt-LogFile {
    param (
        [string]$logFilePath
    )
    
    $key = "MySuperSecretKey123!"  # Clé de cryptage (à stocker de manière sécurisée)
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Key = [Text.Encoding]::UTF8.GetBytes($key)
    $aes.IV = New-Object Byte[] 16
    
    $fileContent = Get-Content -Path $logFilePath -Raw
    $encryptedContent = [System.Convert]::ToBase64String($aes.CreateEncryptor().TransformFinalBlock([Text.Encoding]::UTF8.GetBytes($fileContent), 0, $fileContent.Length))
    Set-Content -Path $logFilePath -Value $encryptedContent
    Log-Message "Fichier de journal crypté: $logFilePath"
}

# Fonction pour arrêter tous les services suspects
function Stop-SuspiciousServices {
    try {
        $suspiciousServices = @("maliciousService", "unwantedService")
        foreach ($service in $suspiciousServices) {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Stop-Service -Name $service -Force
                Log-Message "Service suspect arrêté: ${service}"
                Send-AlertEmail -subject "Service suspect arrêté" -body "Service suspect arrêté: ${service}"
            }
        }
    } catch {
        Log-Message "Erreur lors de l'arrêt des services suspects: $($_.Exception.Message). Vérifiez que vous avez les droits d'administration."
    }
}

function Monitor-OpenPorts {
    $allowedPorts = @("80", "443", "22")
    $openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }

    foreach ($port in $openPorts) {
        if (-not ($allowedPorts -contains $port.LocalPort)) {
            Log-Message "Port non autorisé détecté: $($port.LocalPort) utilisé par $($port.OwningProcess)"
            Add-FirewallRuleIfNotExist -ipAddress $port.RemoteAddress
        }
    }
}

# Fonction pour surveiller les fichiers et dossiers suspects avec Deep Scan (suite)
function DeepScan-SuspiciousFiles {
    try {
        $suspiciousFiles = Get-Content -Path $suspiciousFilesFile -ErrorAction SilentlyContinue
        foreach ($filePath in $suspiciousFiles) {
            if (Test-Path $filePath) {
                $fileHash = Get-FileHash -Path $filePath -Algorithm SHA256
                Log-Message "Fichier suspect détecté: ${filePath} avec hash $($fileHash.Hash)"
            } else {
                Log-Message "Le fichier suspect suivant n'existe plus: ${filePath}"
            }
        }
    } catch {
        Log-Message "Erreur lors de l'analyse approfondie des fichiers suspects: $($_.Exception.Message)."
    }
}

# Fonction pour enregistrer et finaliser le rapport de Deep Scan
function Finalize-DeepScan {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $report = @"
Rapport de Deep Scan - $timestamp

Références :
  - Logs : $logFile
  - IPs suspectes : $suspiciousIpsFile
  - Fichiers suspects : $suspiciousFilesFile

Résumé des résultats :
  - Connexions réseau suspectes traitées
  - Processus suspects stoppés
  - Services suspects arrêtés
  - Comptes utilisateurs malveillants désactivés
  - Paramètres de sécurité renforcés
  - Fichiers et dossiers suspects vérifiés
"@

    try {
        $reportFile = "C:\log\DeepScanReport_${timestamp}.txt"
        $report | Out-File -FilePath $reportFile -Encoding utf8
        Log-Message "Rapport final de Deep Scan généré: $reportFile"
        Send-AlertEmail -subject "Rapport final de Deep Scan" -body "Le rapport final de Deep Scan est disponible à l'emplacement suivant: $reportFile"
    } catch {
        Log-Message "Erreur lors de la génération du rapport final: $($_.Exception.Message)."
    }
}

# Fonction principale pour lancer toutes les analyses
function Run-SecurityScan {
    Log-Message "Lancement du scan de sécurité complet..."

    # Vérifier les connexions réseau
    Monitor-NetworkConnections

    # Vérifier les processus suspects
    Monitor-Processes

    # Désactiver les comptes utilisateurs malveillants
    Disable-MaliciousUserAccounts

    # Renforcer les paramètres de sécurité
    Harden-SecuritySettings

    # Arrêter les services suspects
    Stop-SuspiciousServices

    # Analyser les fichiers suspects
    DeepScan-SuspiciousFiles

    # Finaliser et enregistrer le rapport
    Finalize-DeepScan

    Log-Message "Scan de sécurité complet terminé."
}

# Exécuter le scan de sécurité
Run-SecurityScan

