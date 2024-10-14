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

if (-not (Test-Path $jdkExtractPath)) {
    Write-Output "Téléchargement du JDK..."
    Invoke-WebRequest -Uri $jdkInstallerUrl -OutFile $jdkZipPath

    Write-Output "Décompression du JDK..."
    Expand-Archive -Path $jdkZipPath -DestinationPath $jdkExtractPath -Force

    Write-Output "Configuration du PATH..."
    $jdkBinPath = Join-Path $jdkExtractPath "jdk-17.0.12\bin"
    $env:Path = "$jdkBinPath;$env:Path"
    [System.Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

    Write-Output "Suppression du fichier zip..."
    Remove-Item -Path $jdkZipPath -Force
} else {
    Write-Output "Le JDK est déjà installé."
}

# Création des fichiers Java
$srcFolder = "C:\TCPsystemSecureAutonomous\src"
$tcpSystemMonitorFile = "$srcFolder\com\tcpsystem\TCPSystemMonitor.java"
$securityScanFile = "$srcFolder\com\tcpsystem\SecurityScan.java"

Write-Output "Création des fichiers Java..."

# TCPSystemMonitor.java content
$tcpSystemMonitorContent = @"
package com.tcpsystem;

package com.tcpsystem;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class TCPSystemMonitor {
    private static String LOG_FILE;
    private static DefaultTableModel tcpModel;
    private static DefaultTableModel udpModel;
    private static ExecutorService executor;
    private static boolean monitoring = false;

    static {
        Properties props = new Properties();
        try (InputStream input = new FileInputStream("config.properties")) {
            props.load(input);
            LOG_FILE = props.getProperty("log.file", "C:/TCPsystemSecureAutonomous/logs/tcp_connections.txt");
        } catch (IOException e) {
            System.err.println("Configuration file error: " + e.getMessage());
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        // Configuration de l'interface graphique
        JFrame frame = new JFrame("TCP & UDP System Monitor");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 600);

        JTabbedPane tabbedPane = new JTabbedPane();

        // Onglet des connexions TCP
        JPanel tcpPanel = new JPanel(new BorderLayout());
        tcpModel = new DefaultTableModel(new Object[]{"Timestamp", "Protocol", "Address"}, 0);
        JTable tcpTable = new JTable(tcpModel);
        tcpPanel.add(new JScrollPane(tcpTable), BorderLayout.CENTER);
        tabbedPane.addTab("TCP Connections", tcpPanel);

        // Onglet des connexions UDP
        JPanel udpPanel = new JPanel(new BorderLayout());
        udpModel = new DefaultTableModel(new Object[]{"Timestamp", "Protocol", "Address"}, 0);
        JTable udpTable = new JTable(udpModel);
        udpPanel.add(new JScrollPane(udpTable), BorderLayout.CENTER);
        tabbedPane.addTab("UDP Connections", udpPanel);

        frame.add(tabbedPane, BorderLayout.CENTER);

        // Panel pour l'entrée des ports
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new FlowLayout());

        inputPanel.add(new JLabel("Start Port:"));
        JTextField startPortField = new JTextField(5);
        inputPanel.add(startPortField);

        inputPanel.add(new JLabel("End Port:"));
        JTextField endPortField = new JTextField(5);
        inputPanel.add(endPortField);

        JButton startButton = new JButton("Start Monitoring");
        startButton.addActionListener(e -> {
            int startPort;
            int endPort;
            try {
                startPort = Integer.parseInt(startPortField.getText());
                endPort = Integer.parseInt(endPortField.getText());
                if (startPort < 1 || endPort > 65535 || startPort > endPort) {
                    throw new NumberFormatException();
                }
                startMonitoring(startPort, endPort);
                startButton.setEnabled(false);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(frame, "Invalid port numbers. Please enter valid integer values.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        inputPanel.add(startButton);

        JButton stopButton = new JButton("Stop Monitoring");
        stopButton.addActionListener(e -> {
            stopMonitoring();
            startButton.setEnabled(true);
        });

        inputPanel.add(stopButton);

        frame.add(inputPanel, BorderLayout.SOUTH);
        frame.setVisible(true);

        startLogFileViewer();
    }

    static void startMonitoring(int startPort, int endPort) {
        if (monitoring) return;
        monitoring = true;
        int threadPoolSize = Math.max(endPort - startPort + 1, 10);
        executor = Executors.newFixedThreadPool(threadPoolSize);

        logToFile("Monitoring started on ports " + startPort + " to " + endPort + ".");

        for (int port = startPort; port <= endPort; port++) {
            final int p = port;
            executor.submit(() -> monitorTCPConnections(p));
            executor.submit(() -> monitorUDPConnections(p));
        }
    }

    private static void stopMonitoring() {
        if (!monitoring) return;
        monitoring = false;
        logToFile("Monitoring stopped.");
        executor.shutdown();
        try {
            if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logToFile("Monitoring interruption error: " + e.getMessage());
        }
    }

    private static void monitorTCPConnections(int port) {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logToFile("TCP Monitoring started on port " + port + ".");
            while (monitoring) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    handleClient(clientSocket, "TCP");
                } catch (IOException e) {
                    logToFile("TCP Error accepting connection on port " + port + ": " + e.getMessage());
                }
            }
        } catch (IOException e) {
            logToFile("TCP ServerSocket error on port " + port + ": " + e.getMessage());
        }
    }

    private static void monitorUDPConnections(int port) {
        try (DatagramSocket datagramSocket = new DatagramSocket(port)) {
            logToFile("UDP Monitoring started on port " + port + ".");
            byte[] buffer = new byte[1024];
            while (monitoring) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                try {
                    datagramSocket.receive(packet);
                    String clientAddress = packet.getAddress().toString() + ":" + packet.getPort();
                    logConnection(clientAddress, "UDP");
                } catch (IOException e) {
                    logToFile("UDP Error receiving packet on port " + port + ": " + e.getMessage());
                }
            }
        } catch (SocketException e) {
            logToFile("UDP DatagramSocket error on port " + port + ": " + e.getMessage());
        }
    }

    private static void handleClient(Socket clientSocket, String protocol) {
        try {
            String clientAddress = clientSocket.getInetAddress().toString() + ":" + clientSocket.getPort();
            logConnection(clientAddress, protocol);
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                logToFile("Error closing client socket: " + e.getMessage());
            }
        }
    }

    private static void logConnection(String clientAddress, String protocol) {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        String message = timestamp + " - " + protocol + " Connection from " + clientAddress;
        logToFile(message);

        SwingUtilities.invokeLater(() -> {
            if ("TCP".equals(protocol)) {
                tcpModel.addRow(new Object[]{timestamp, protocol, clientAddress});
            } else if ("UDP".equals(protocol)) {
                udpModel.addRow(new Object[]{timestamp, protocol, clientAddress});
            }
        });
    }

    private static void logToFile(String message) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
            writer.write(message);
            writer.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void startLogFileViewer() {
        Timer timer = new Timer(5000, e -> refreshLogFileView());
        timer.start();
    }

    private static void refreshLogFileView() {
        try (BufferedReader reader = new BufferedReader(new FileReader(LOG_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("TCP")) {
                    String[] parts = line.split(" - ");
                    if (parts.length == 2) {
                        String timestamp = parts[0];
                        String[] details = parts[1].split(" Connection from ");
                        if (details.length == 2) {
                            String protocol = "TCP";
                            String address = details[1];
                            SwingUtilities.invokeLater(() -> tcpModel.addRow(new Object[]{timestamp, protocol, address}));
                        }
                    }
                } else if (line.contains("UDP")) {
                    String[] parts = line.split(" - ");
                    if (parts.length == 2) {
                        String timestamp = parts[0];
                        String[] details = parts[1].split(" Connection from ");
                        if (details.length == 2) {
                            String protocol = "UDP";
                            String address = details[1];
                            SwingUtilities.invokeLater(() -> udpModel.addRow(new Object[]{timestamp, protocol, address}));
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

"@
$tcpSystemMonitorContent | Out-File -FilePath $tcpSystemMonitorFile -Force


# SecurityScan.java content
$securityScannerContent = @"
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
"@
$securityScannerContent | Out-File -FilePath $securityScanFile -Force

Write-Output "Fichiers Java créés."

# Compilation des fichiers Java
Write-Output "Compilation des fichiers Java..."
$javacPath = Join-Path $jdkExtractPath "jdk-17.0.12\bin\javac.exe"

& $javacPath -d "C:\TCPsystemSecureAutonomous\bin" "$srcFolder\com\tcpsystem\*.java"

Write-Output "Compilation réussie."

# Exécution du programme Java
Write-Output "Exécution du programme Java..."
$javaPath = Join-Path $jdkExtractPath "jdk-17.0.12\bin\java.exe"

Start-Process -NoNewWindow -FilePath $javaPath -ArgumentList "-cp C:\TCPsystemSecureAutonomous\bin com.tcpsystem.TCPSystemMonitor"

# Démarrage de l'analyse de sécurité
Write-Output "Démarrage de l'analyse de sécurité..."
Start-Process -NoNewWindow -FilePath $javaPath -ArgumentList "-cp C:\TCPsystemSecureAutonomous\bin com.tcpsystem.SecurityScanner"

Write-Output "Configuration terminée. Le système est maintenant en cours d'exécution."
