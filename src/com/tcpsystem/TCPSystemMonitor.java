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
