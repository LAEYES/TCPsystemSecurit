package com.tcpsystem;


import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.Date;



public class SecurityScanner {

    private static final String LOG_FILE = "C:/log/securityLog.log";
    private static final String SUSPICIOUS_IPS_FILE = "C:/log/suspiciousIps.txt";
    private static final String SUSPICIOUS_FILES_FILE = "C:/log/suspiciousFiles.txt";
 

    public static void main(String[] args) {
        try {
            checkAndCreateDirectories();

            logMessage("Lancement du scan de sécurité complet...");
            monitorNetworkConnections();
            monitorProcesses();
            disableMaliciousUserAccounts();
            hardenSecuritySettings();
            stopSuspiciousServices();
            deepScanSuspiciousFiles();
            finalizeDeepScan();
            logMessage("Scan de sécurité complet terminé.");

        } catch (Exception e) {
            logMessage("Erreur lors de l'exécution du scan de sécurité: " + e.getMessage());
        }
    }

    /**
     * Vérifie et crée les répertoires nécessaires pour les fichiers de log et d'alerte.
     */
    private static void checkAndCreateDirectories() throws IOException {
        Path logFilePath = Paths.get(LOG_FILE);
        Path suspiciousIpsFilePath = Paths.get(SUSPICIOUS_IPS_FILE);
        Path suspiciousFilesFilePath = Paths.get(SUSPICIOUS_FILES_FILE);

        createFileIfNotExists(logFilePath);
        createFileIfNotExists(suspiciousIpsFilePath);
        createFileIfNotExists(suspiciousFilesFilePath);
    }

    /**
     * Crée le fichier s'il n'existe pas déjà.
     */
    private static void createFileIfNotExists(Path path) throws IOException {
        if (!Files.exists(path.getParent())) {
            Files.createDirectories(path.getParent());
        }
        if (!Files.exists(path)) {
            Files.createFile(path);
        }
    }

    /**
     * Enregistre un message dans le fichier de log avec un horodatage.
     */
    private static void logMessage(String message) {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        String logEntry = timestamp + " - " + message;

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
            writer.write(logEntry);
            writer.newLine();
        } catch (IOException e) {
            System.err.println("Erreur lors de l'écriture dans le fichier de log: " + e.getMessage());
        }
    }

    /**
     * Envoie un e-mail d'alerte en cas de détection de comportement suspect.
     */

    /**
     * Surveille les connexions réseau à l'aide de "netstat" et enregistre les informations.
     */
    private static void monitorNetworkConnections() {
        logMessage("Vérification des connexions réseau...");

        try {
            Process process = Runtime.getRuntime().exec("netstat -an");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("ESTABLISHED")) {
                    logMessage("Connexion établie détectée: " + line);
                }
            }

        } catch (IOException e) {
            logMessage("Erreur lors de la surveillance des connexions réseau: " + e.getMessage());
        }
    }

    /**
     * Surveille les processus actifs sur la machine.
     */
    private static void monitorProcesses() {
        logMessage("Vérification des processus en cours...");

        try {
            Process process = Runtime.getRuntime().exec("tasklist");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                logMessage("Processus actif: " + line);
            }

        } catch (IOException e) {
            logMessage("Erreur lors de la vérification des processus: " + e.getMessage());
        }
    }

    /**
     * Désactive les comptes utilisateurs jugés malveillants.
     */
    private static void disableMaliciousUserAccounts() {
        logMessage("Désactivation des comptes utilisateurs malveillants...");
        // Exemple : Utiliser un appel système pour désactiver les comptes
    }

    /**
     * Renforce les paramètres de sécurité du système.
     */
    private static void hardenSecuritySettings() {
        logMessage("Renforcement des paramètres de sécurité...");
        // Exemple : Appliquer des paramètres spécifiques pour renforcer la sécurité
    }

    /**
     * Arrête les services jugés suspects.
     */
    private static void stopSuspiciousServices() {
        logMessage("Arrêt des services suspects...");
        // Exemple : Utiliser un appel système pour stopper des services dangereux
    }

    /**
     * Analyse les fichiers suspects pour détecter les menaces.
     */
    private static void deepScanSuspiciousFiles() {
        logMessage("Scan des fichiers suspects...");
        
        try {
            // Chemin vers le script PowerShell
            String scriptPath = "C:/path/to/deepscan_secure.ps1"; // Modifiez ce chemin en conséquence
    
            // Commande pour exécuter le script PowerShell
            String command = "powershell.exe -ExecutionPolicy Bypass -File " + scriptPath;
    
            // Exécution de la commande
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    
            String line;
            while ((line = reader.readLine()) != null) {
                logMessage("Sortie du script de scan : " + line);
            }
    
            process.waitFor(); // Attendre la fin du processus
    
        } catch (IOException | InterruptedException e) {
            logMessage("Erreur lors de l'exécution du scan des fichiers suspects: " + e.getMessage());
        }
    }
    
    /**
     * Finalise le scan et produit un rapport final.
     */
    private static void finalizeDeepScan() {
        logMessage("Finalisation du scan de sécurité...");
        // Exemple : Enregistrer un rapport de synthèse à la fin du scan
    }
}