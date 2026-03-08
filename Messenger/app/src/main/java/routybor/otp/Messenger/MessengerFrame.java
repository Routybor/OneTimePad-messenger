package routybor.otp.Messenger;

import java.io.IOException;
import javax.swing.SwingUtilities;
import static routybor.otp.Messenger.Server.startServer;
import static routybor.otp.Messenger.Server.stopServer;
import java.util.List;
import java.util.ArrayList;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

public class MessengerFrame extends javax.swing.JFrame {

    private static final java.util.logging.Logger logger = java.util.logging.Logger.getLogger(MessengerFrame.class.getName());
    public String selectedPeerAddress;
    private java.util.List<ActiveContact> contacts;
    private ActiveContact selectedContact;

    private static int SERVER_PORT = 5001;
    private static String SERVER_IP = getLocalIpAddress();

    private static final int W = 700;
    private static final int H = 600;

    private static class ActiveContact {

        String ip;
        int port;
        Client.Connection connection;
        List<String> messages;

        ActiveContact(String ip, int port) {
            this.ip = ip;
            this.port = port;
            this.connection = null;
            this.messages = new ArrayList<>();
        }
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        addPeerDialog = new javax.swing.JDialog();
        addPeerPanel = new javax.swing.JPanel();
        peerIpInout = new java.awt.TextField();
        peerPortInput = new java.awt.TextField();
        addPeerButton = new javax.swing.JButton();
        peerIpLabel = new javax.swing.JLabel();
        peerPortLabel = new javax.swing.JLabel();
        addPeerLabel = new javax.swing.JLabel();
        settingsDialog = new javax.swing.JDialog();
        settinsPanel = new javax.swing.JPanel();
        settingsLabel = new javax.swing.JLabel();
        userIpLabel = new javax.swing.JLabel();
        userIpInput = new java.awt.TextField();
        userPortLabel = new javax.swing.JLabel();
        userPortInput = new java.awt.TextField();
        saveSettings = new javax.swing.JButton();
        mainLayeredPane = new javax.swing.JLayeredPane();
        greetingGif = new javax.swing.JLabel();
        mainPanel = new javax.swing.JPanel();
        settings = new javax.swing.JButton();
        addContact = new javax.swing.JButton();
        contactLabel = new javax.swing.JLabel();
        contactList = new java.awt.List();
        chattLabel = new javax.swing.JLabel();
        deleteContact = new javax.swing.JButton();
        sendMessage = new javax.swing.JButton();
        messageText = new java.awt.TextField();
        chatPanel = new javax.swing.JEditorPane();

        addPeerDialog.setAlwaysOnTop(true);
        addPeerDialog.setBackground(new java.awt.Color(102, 102, 102));
        addPeerDialog.setFont(new java.awt.Font("Old English Text MT", 0, 12)); // NOI18N
        addPeerDialog.setModal(true);

        addPeerPanel.setBackground(new java.awt.Color(102, 102, 102));

        peerIpInout.setBackground(new java.awt.Color(51, 51, 51));
        peerIpInout.setFont(new java.awt.Font("Old English Text MT", 0, 18)); // NOI18N
        peerIpInout.setForeground(new java.awt.Color(255, 255, 255));

        peerPortInput.setBackground(new java.awt.Color(51, 51, 51));
        peerPortInput.setFont(new java.awt.Font("Old English Text MT", 0, 18)); // NOI18N
        peerPortInput.setForeground(new java.awt.Color(255, 255, 255));

        addPeerButton.setBackground(new java.awt.Color(51, 51, 51));
        addPeerButton.setFont(new java.awt.Font("Old English Text MT", 1, 18)); // NOI18N
        addPeerButton.setForeground(new java.awt.Color(255, 255, 255));
        addPeerButton.setText("Add contact");
        addPeerButton.setAlignmentX(0.5F);
        addPeerButton.setBorderPainted(false);
        addPeerButton.setFocusable(false);
        addPeerButton.addActionListener(this::addPeerButtonActionPerformed);

        peerIpLabel.setFont(new java.awt.Font("Old English Text MT", 1, 18)); // NOI18N
        peerIpLabel.setForeground(new java.awt.Color(255, 255, 255));
        peerIpLabel.setText("Peer IP");

        peerPortLabel.setFont(new java.awt.Font("Old English Text MT", 1, 18)); // NOI18N
        peerPortLabel.setForeground(new java.awt.Color(255, 255, 255));
        peerPortLabel.setText("Peer port");

        addPeerLabel.setFont(new java.awt.Font("Old English Text MT", 0, 30)); // NOI18N
        addPeerLabel.setForeground(new java.awt.Color(255, 255, 255));
        addPeerLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        addPeerLabel.setText("Enter peer's data");
        addPeerLabel.setToolTipText("");

        javax.swing.GroupLayout addPeerPanelLayout = new javax.swing.GroupLayout(addPeerPanel);
        addPeerPanel.setLayout(addPeerPanelLayout);
        addPeerPanelLayout.setHorizontalGroup(
            addPeerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(addPeerLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 433, Short.MAX_VALUE)
            .addGroup(addPeerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(addPeerPanelLayout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(addPeerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(peerIpInout, javax.swing.GroupLayout.DEFAULT_SIZE, 409, Short.MAX_VALUE)
                        .addComponent(peerPortInput, javax.swing.GroupLayout.DEFAULT_SIZE, 409, Short.MAX_VALUE)
                        .addComponent(addPeerButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(peerIpLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(peerPortLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addContainerGap()))
        );
        addPeerPanelLayout.setVerticalGroup(
            addPeerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(addPeerPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(addPeerLabel)
                .addContainerGap(175, Short.MAX_VALUE))
            .addGroup(addPeerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                .addGroup(addPeerPanelLayout.createSequentialGroup()
                    .addGap(49, 49, 49)
                    .addComponent(peerIpLabel)
                    .addGap(3, 3, 3)
                    .addComponent(peerIpInout, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(peerPortLabel)
                    .addGap(2, 2, 2)
                    .addComponent(peerPortInput, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(addPeerButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addContainerGap()))
        );

        javax.swing.GroupLayout addPeerDialogLayout = new javax.swing.GroupLayout(addPeerDialog.getContentPane());
        addPeerDialog.getContentPane().setLayout(addPeerDialogLayout);
        addPeerDialogLayout.setHorizontalGroup(
            addPeerDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(addPeerPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        addPeerDialogLayout.setVerticalGroup(
            addPeerDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(addPeerPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        settingsDialog.setModal(true);

        settinsPanel.setBackground(new java.awt.Color(102, 102, 102));

        settingsLabel.setFont(new java.awt.Font("Old English Text MT", 0, 30)); // NOI18N
        settingsLabel.setForeground(new java.awt.Color(255, 255, 255));
        settingsLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        settingsLabel.setText("Settings");
        settingsLabel.setToolTipText("");

        userIpLabel.setFont(new java.awt.Font("Old English Text MT", 1, 18)); // NOI18N
        userIpLabel.setForeground(new java.awt.Color(255, 255, 255));
        userIpLabel.setText("Your IP");

        userIpInput.setBackground(new java.awt.Color(51, 51, 51));
        userIpInput.setFont(new java.awt.Font("Old English Text MT", 0, 18)); // NOI18N
        userIpInput.setForeground(new java.awt.Color(255, 255, 255));

        userPortLabel.setFont(new java.awt.Font("Old English Text MT", 1, 18)); // NOI18N
        userPortLabel.setForeground(new java.awt.Color(255, 255, 255));
        userPortLabel.setText("Your port");

        userPortInput.setBackground(new java.awt.Color(51, 51, 51));
        userPortInput.setFont(new java.awt.Font("Old English Text MT", 0, 18)); // NOI18N
        userPortInput.setForeground(new java.awt.Color(255, 255, 255));

        saveSettings.setBackground(new java.awt.Color(51, 51, 51));
        saveSettings.setFont(new java.awt.Font("Old English Text MT", 1, 18)); // NOI18N
        saveSettings.setForeground(new java.awt.Color(255, 255, 255));
        saveSettings.setText("Save");
        saveSettings.setAlignmentX(0.5F);
        saveSettings.setBorderPainted(false);
        saveSettings.setFocusable(false);
        saveSettings.addActionListener(this::saveSettingsActionPerformed);

        javax.swing.GroupLayout settinsPanelLayout = new javax.swing.GroupLayout(settinsPanel);
        settinsPanel.setLayout(settinsPanelLayout);
        settinsPanelLayout.setHorizontalGroup(
            settinsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(settingsLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(settinsPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(settinsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(saveSettings, javax.swing.GroupLayout.DEFAULT_SIZE, 409, Short.MAX_VALUE)
                    .addComponent(userPortInput, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(userPortLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(userIpInput, javax.swing.GroupLayout.DEFAULT_SIZE, 409, Short.MAX_VALUE)
                    .addComponent(userIpLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        settinsPanelLayout.setVerticalGroup(
            settinsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(settinsPanelLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(settingsLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(userIpLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(userIpInput, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(userPortLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(userPortInput, javax.swing.GroupLayout.PREFERRED_SIZE, 27, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(saveSettings)
                .addContainerGap())
        );

        javax.swing.GroupLayout settingsDialogLayout = new javax.swing.GroupLayout(settingsDialog.getContentPane());
        settingsDialog.getContentPane().setLayout(settingsDialogLayout);
        settingsDialogLayout.setHorizontalGroup(
            settingsDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(settinsPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        settingsDialogLayout.setVerticalGroup(
            settingsDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(settinsPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Visio");
        setBackground(new java.awt.Color(0, 0, 0));
        setForeground(new java.awt.Color(51, 51, 51));
        setMaximumSize(new java.awt.Dimension(700, 600));
        setMinimumSize(new java.awt.Dimension(700, 600));
        setPreferredSize(new java.awt.Dimension(700, 600));
        setResizable(false);
        setSize(new java.awt.Dimension(700, 600));

        mainLayeredPane.setAutoscrolls(true);
        mainLayeredPane.setMaximumSize(new java.awt.Dimension(700, 600));
        mainLayeredPane.setMinimumSize(new java.awt.Dimension(700, 600));
        mainLayeredPane.setRequestFocusEnabled(false);

        greetingGif.setAlignmentX(0.5F);
        greetingGif.setPreferredSize(new java.awt.Dimension(700, 600));

        mainPanel.setBackground(new java.awt.Color(102, 102, 102));
        mainPanel.setAlignmentX(0.0F);
        mainPanel.setAlignmentY(0.0F);
        mainPanel.setAutoscrolls(true);
        mainPanel.setPreferredSize(new java.awt.Dimension(700, 600));

        settings.setBackground(new java.awt.Color(51, 51, 51));
        settings.setFont(new java.awt.Font("Old English Text MT", 0, 24)); // NOI18N
        settings.setForeground(new java.awt.Color(255, 255, 255));
        settings.setText("...");
        settings.setBorder(null);
        settings.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        settings.setFocusPainted(false);
        settings.addActionListener(this::settingsActionPerformed);

        addContact.setBackground(new java.awt.Color(51, 51, 51));
        addContact.setFont(new java.awt.Font("Old English Text MT", 0, 24)); // NOI18N
        addContact.setForeground(new java.awt.Color(255, 255, 255));
        addContact.setText("Add");
        addContact.setBorder(null);
        addContact.setBorderPainted(false);
        addContact.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        addContact.setFocusPainted(false);
        addContact.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                addContactMouseClicked(evt);
            }
        });
        addContact.addActionListener(this::addContactActionPerformed);

        contactLabel.setBackground(new java.awt.Color(51, 51, 51));
        contactLabel.setFont(new java.awt.Font("Old English Text MT", 0, 24)); // NOI18N
        contactLabel.setForeground(new java.awt.Color(255, 255, 255));
        contactLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        contactLabel.setText("Contacts");
        contactLabel.setAlignmentY(0.0F);
        contactLabel.setOpaque(true);

        contactList.setBackground(new java.awt.Color(51, 51, 51));
        contactList.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        contactList.setFont(new java.awt.Font("Old English Text MT", 0, 18)); // NOI18N
        contactList.setForeground(new java.awt.Color(255, 255, 255));
        contactList.addItemListener(this::contactListItemStateChanged);

        chattLabel.setBackground(new java.awt.Color(51, 51, 51));
        chattLabel.setFont(new java.awt.Font("Old English Text MT", 0, 24)); // NOI18N
        chattLabel.setForeground(new java.awt.Color(255, 255, 255));
        chattLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        chattLabel.setText("Chat");
        chattLabel.setAlignmentY(0.0F);
        chattLabel.setOpaque(true);

        deleteContact.setBackground(new java.awt.Color(51, 51, 51));
        deleteContact.setFont(new java.awt.Font("Old English Text MT", 0, 24)); // NOI18N
        deleteContact.setForeground(new java.awt.Color(255, 255, 255));
        deleteContact.setText("Delete");
        deleteContact.setBorder(null);
        deleteContact.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        deleteContact.setFocusPainted(false);
        deleteContact.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                deleteContactMouseClicked(evt);
            }
        });

        sendMessage.setBackground(new java.awt.Color(51, 51, 51));
        sendMessage.setFont(new java.awt.Font("Old English Text MT", 0, 24)); // NOI18N
        sendMessage.setForeground(new java.awt.Color(255, 255, 255));
        sendMessage.setText("Send");
        sendMessage.setBorder(null);
        sendMessage.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        sendMessage.setFocusPainted(false);
        sendMessage.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                sendMessageMouseClicked(evt);
            }
        });
        sendMessage.addActionListener(this::sendMessageActionPerformed);

        messageText.setBackground(new java.awt.Color(51, 51, 51));
        messageText.setCursor(new java.awt.Cursor(java.awt.Cursor.TEXT_CURSOR));
        messageText.setFont(new java.awt.Font("Old English Text MT", 1, 18)); // NOI18N
        messageText.setForeground(new java.awt.Color(255, 255, 255));

        chatPanel.setBackground(new java.awt.Color(51, 51, 51));
        chatPanel.setContentType(""); // NOI18N
        chatPanel.setFont(new java.awt.Font("Old English Text MT", 0, 18)); // NOI18N
        chatPanel.setForeground(new java.awt.Color(255, 255, 255));
        chatPanel.setAutoscrolls(false);
        chatPanel.setMargin(new java.awt.Insets(0, 0, 0, 0));

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(addContact, javax.swing.GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(deleteContact, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(contactLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(contactList, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                        .addComponent(messageText, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(sendMessage, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(chatPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 462, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                        .addComponent(chattLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(settings, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(contactLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(chattLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(settings, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(chatPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 500, Short.MAX_VALUE)
                    .addComponent(contactList, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(addContact, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
                        .addComponent(deleteContact, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE))
                    .addComponent(messageText, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(sendMessage, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        mainLayeredPane.setLayer(greetingGif, javax.swing.JLayeredPane.DEFAULT_LAYER);
        mainLayeredPane.setLayer(mainPanel, javax.swing.JLayeredPane.DEFAULT_LAYER);

        javax.swing.GroupLayout mainLayeredPaneLayout = new javax.swing.GroupLayout(mainLayeredPane);
        mainLayeredPane.setLayout(mainLayeredPaneLayout);
        mainLayeredPaneLayout.setHorizontalGroup(
            mainLayeredPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 727, Short.MAX_VALUE)
            .addGroup(mainLayeredPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(mainLayeredPaneLayout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(mainPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 703, Short.MAX_VALUE)
                    .addContainerGap(122, Short.MAX_VALUE)))
            .addGroup(mainLayeredPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(mainLayeredPaneLayout.createSequentialGroup()
                    .addGap(64, 64, 64)
                    .addComponent(greetingGif, javax.swing.GroupLayout.PREFERRED_SIZE, 663, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
        );
        mainLayeredPaneLayout.setVerticalGroup(
            mainLayeredPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 611, Short.MAX_VALUE)
            .addGroup(mainLayeredPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(mainLayeredPaneLayout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(mainPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 604, Short.MAX_VALUE)
                    .addContainerGap()))
            .addGroup(mainLayeredPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(mainLayeredPaneLayout.createSequentialGroup()
                    .addGap(304, 304, 304)
                    .addComponent(greetingGif, javax.swing.GroupLayout.PREFERRED_SIZE, 15, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(309, Short.MAX_VALUE)))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(mainLayeredPane, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGap(184, 184, 184))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(mainLayeredPane, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addContact;
    private javax.swing.JButton addPeerButton;
    private javax.swing.JDialog addPeerDialog;
    private javax.swing.JLabel addPeerLabel;
    private javax.swing.JPanel addPeerPanel;
    private javax.swing.JEditorPane chatPanel;
    private javax.swing.JLabel chattLabel;
    private javax.swing.JLabel contactLabel;
    private java.awt.List contactList;
    private javax.swing.JButton deleteContact;
    private javax.swing.JLabel greetingGif;
    private javax.swing.JLayeredPane mainLayeredPane;
    private javax.swing.JPanel mainPanel;
    private java.awt.TextField messageText;
    private java.awt.TextField peerIpInout;
    private javax.swing.JLabel peerIpLabel;
    private java.awt.TextField peerPortInput;
    private javax.swing.JLabel peerPortLabel;
    private javax.swing.JButton saveSettings;
    private javax.swing.JButton sendMessage;
    private javax.swing.JButton settings;
    private javax.swing.JDialog settingsDialog;
    private javax.swing.JLabel settingsLabel;
    private javax.swing.JPanel settinsPanel;
    private java.awt.TextField userIpInput;
    private javax.swing.JLabel userIpLabel;
    private java.awt.TextField userPortInput;
    private javax.swing.JLabel userPortLabel;
    // End of variables declaration//GEN-END:variables

    private void addPeerButtonActionPerformed(java.awt.event.ActionEvent evt) {
        validateAndAddContact();
    }

    private void addContactMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_addContactMouseClicked

        addPeerDialog.pack();

        int x = this.getLocation().x + (this.getWidth() - addPeerDialog.getWidth()) / 2;
        int y = this.getLocation().y + (this.getHeight() - addPeerDialog.getHeight()) / 2;

        addPeerDialog.setLocation(x, y);
        addPeerDialog.setVisible(true);

    }//GEN-LAST:event_addContactMouseClicked

    private void addContactActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addContactActionPerformed
        addPeerDialog.pack();

        int x = this.getLocation().x + (this.getWidth() - addPeerDialog.getWidth()) / 2;
        int y = this.getLocation().y + (this.getHeight() - addPeerDialog.getHeight()) / 2;

        addPeerDialog.setLocation(x, y);
        addPeerDialog.setVisible(true);
    }//GEN-LAST:event_addContactActionPerformed

    private void contactListItemStateChanged(java.awt.event.ItemEvent evt) {
        int idx = contactList.getSelectedIndex();

        if (idx < 0 || idx >= contacts.size()) {
            selectedPeerAddress = null;
            selectedContact = null;
            return;
        }

        ActiveContact contact = contacts.get(idx);
        selectedPeerAddress = contact.ip + ":" + contact.port;
        selectedContact = contact;

        connectToSelectedContact(selectedContact);
        updateChatPanel(contact);
    }

    private void deleteContactMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_deleteContactMouseClicked

        int idx = contactList.getSelectedIndex();
        if (idx < 0) {
            return;
        }

        ActiveContact toDelete = contacts.get(idx);
        int confirm = javax.swing.JOptionPane.showConfirmDialog(this,
                String.format("Delete %s:%s?", toDelete.ip, toDelete.port), "Confirm", 0);

        if (confirm == 0) {
            if (toDelete.connection != null) {
                try {
                    toDelete.connection.close();
                } catch (Exception ignored) {
                }
            }
            contacts.remove(idx);
            selectedPeerAddress = null;
            selectedContact = null;
            chatPanel.setText("");
            updateContactList();
        }

    }//GEN-LAST:event_deleteContactMouseClicked

    private void sendMessageMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_sendMessageMouseClicked
        sendMessageActionPerformed(null);
    }//GEN-LAST:event_sendMessageMouseClicked

    private void sendMessageActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendMessageActionPerformed
        if (selectedContact == null) {
            messageText.setText("");
            return;
        }

        String msg = messageText.getText();
        if (msg == null) {
            msg = "";
        }
        msg = msg.trim();
        if (msg.isEmpty()) {
            messageText.setText("");
            return;
        }

        selectedContact.messages.add("me- " + msg);
        updateChatPanel(selectedContact);

        if (selectedContact.connection != null) {
            try {
                selectedContact.connection.send(msg);
            } catch (Exception e) {
                try {
                    selectedContact.connection.close();
                } catch (Exception ignored) {
                }
                selectedContact.connection = null;
            }
        }

        messageText.setText("");
    }//GEN-LAST:event_sendMessageActionPerformed

    private void settingsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_settingsActionPerformed
        settingsDialog.pack();

        int x = this.getLocation().x + (this.getWidth() - settingsDialog.getWidth()) / 2;
        int y = this.getLocation().y + (this.getHeight() - settingsDialog.getHeight()) / 2;

        userPortInput.setText(String.valueOf(SERVER_PORT));
        userIpInput.setText(SERVER_IP);
        settingsDialog.setLocation(x, y);
        settingsDialog.setVisible(true);
    }//GEN-LAST:event_settingsActionPerformed

    private void saveSettingsActionPerformed(java.awt.event.ActionEvent evt) {
        String oldIp = SERVER_IP;
        int oldPort = SERVER_PORT;

        String newIp = userIpInput.getText().trim();
        int newPort = parsePortInput();

        if (!validateSettingsInput(newIp, newPort)) {
            return;
        }

        applySettingsChanges(newIp, newPort);

        if (settingsChanged(oldIp, oldPort)) {
            handleSettingsChange();
        }
        settingsDialog.setVisible(false);
    }

    private void updateChatPanel(ActiveContact contact) {
        chatPanel.setText(String.join("\n", contact.messages));
    }

    public MessengerFrame() {
        initComponents();

        try {
            java.net.URL iconUrl = getClass().getResource("/images/icon.png");
            if (iconUrl != null) {
                setIconImage(new javax.swing.ImageIcon(iconUrl).getImage());
            }
        } catch (Exception e) {
            logger.warning(String.format("Failed to load icon - %s", e.getMessage()));
        }

        mainLayeredPane.setLayout(null);
        mainLayeredPane.setPreferredSize(new java.awt.Dimension(W, H));

        mainLayeredPane.remove(mainPanel);
        mainPanel.setBounds(0, 0, W, H);
        mainPanel.setBackground(new java.awt.Color(102, 102, 102));
        mainLayeredPane.add(mainPanel, Integer.valueOf(1));

        mainLayeredPane.remove(greetingGif);
        greetingGif.setBounds(0, 0, W, H);
        greetingGif.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);

        greetingGif.setOpaque(true);
        greetingGif.setBackground(new java.awt.Color(0, 0, 0));
        greetingGif.setText("");

        try {
            java.net.URL imgUrl = getClass().getResource("/images/animation.gif");
            if (imgUrl != null) {
                greetingGif.setIcon(new javax.swing.ImageIcon(imgUrl));
            }
        } catch (Exception e) {
            System.err.println("GIF failed to load - " + e.getMessage());
        }

        mainLayeredPane.add(greetingGif, Integer.valueOf(300));

        this.getContentPane().setLayout(new java.awt.BorderLayout());
        this.getContentPane().add(mainLayeredPane, java.awt.BorderLayout.CENTER);

        setUIComponentsVisible(false);
        greetingGif.setVisible(true);

        javax.swing.Timer timer = new javax.swing.Timer(2200, e -> {
            greetingGif.setVisible(false);
            setUIComponentsVisible(true);
            mainLayeredPane.repaint();
        });
        timer.setRepeats(false);
        timer.start();

        this.setSize(W + 16, H + 39);
        this.setLocationRelativeTo(null);

        contacts = new ArrayList<>();
        selectedContact = null;

        this.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                for (ActiveContact contact : contacts) {
                    if (contact.connection != null) {
                        try {
                            contact.connection.close();
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
        });
    }

    private void setUIComponentsVisible(boolean visible) {
        contactList.setVisible(visible);
        addContact.setVisible(visible);
        chatPanel.setVisible(visible);
        contactLabel.setVisible(visible);
        deleteContact.setVisible(visible);
        chattLabel.setVisible(visible);
    }

    private boolean isValidIpAddress(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private void closeAllConnections() {
        for (ActiveContact contact : contacts) {
            if (contact.connection != null) {
                try {
                    contact.connection.close();
                } catch (Exception ignored) {
                }
                contact.connection = null;
            }
        }
    }

    private static String getLocalIpAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) {
                    continue;
                }
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (SocketException e) {
            logger.warning(String.format("Failed to get local IP address - ", e.getMessage()));
        }
        return "127.0.0.1";
    }

    private static int findFreePort(String ip, int startPort) {
        int port = startPort;
        while (port <= 65535) {
            try (java.net.ServerSocket ss = new java.net.ServerSocket(port, 50, InetAddress.getByName(ip))) {
                return port;
            } catch (IOException e) {
                port++;
            }
        }
        return startPort;
    }

    private void updateContactList() {
        javax.swing.SwingUtilities.invokeLater(() -> {
            contactList.removeAll();
            contactList.setFont(new java.awt.Font("Old English Text MT", 0, 16));

            for (ActiveContact contact : contacts) {
                String entry = contact.ip + ":" + contact.port;
                contactList.add(entry);
            }

            contactList.invalidate();
            contactList.repaint();
        });
    }

    private int parsePortInput() {
        try {
            return Integer.parseInt(userPortInput.getText().trim());
        } catch (NumberFormatException e) {
            javax.swing.JOptionPane.showMessageDialog(this, "Port must be a number", "Input Error", javax.swing.JOptionPane.ERROR_MESSAGE);
            return -1;
        }
    }

    private boolean validateSettingsInput(String newIp, int newPort) {
        if (newPort == -1) {
            return false;
        }
        if (!newIp.isEmpty() && !isValidIpAddress(newIp)) {
            javax.swing.JOptionPane.showMessageDialog(this, "Invalid IP address format", "Input Error", javax.swing.JOptionPane.ERROR_MESSAGE);
            return false;
        }
        return true;
    }

    private void applySettingsChanges(String newIp, int newPort) {
        if (!newIp.isEmpty()) {
            SERVER_IP = newIp;
        }
        SERVER_PORT = newPort;
    }

    private boolean settingsChanged(String oldIp, int oldPort) {
        return !SERVER_IP.equals(oldIp) || SERVER_PORT != oldPort;
    }

    private void handleSettingsChange() {
        closeAllConnections();
        stopServer();
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        SERVER_PORT = findFreePort(SERVER_IP, SERVER_PORT);
        new Thread(() -> startServer(SERVER_IP, SERVER_PORT, this), "ServerThread").start();
    }

    private void connectToSelectedContact(ActiveContact contact) {
        if (contact.connection == null) {
            new Thread(() -> {
                try {
                    Client.Connection conn = Client.connectAndListen(contact.ip, contact.port, msg -> {
                        SwingUtilities.invokeLater(() -> {
                            contact.messages.add("peer- " + msg);
                            updateChatPanel(contact);
                        });
                    }, SERVER_PORT);
                    contact.connection = conn;
                    SwingUtilities.invokeLater(() -> {
                        contact.messages.add("system- chat started");
                        updateChatPanel(contact);
                    });
                } catch (IOException e) {
                    logger.warning(String.format("Failed to connect to %s:%s - %s", contact.ip, contact.port, e.getMessage()));
                    SwingUtilities.invokeLater(() -> {
                        contact.messages.add("system- connection failed: " + e.getMessage());
                        updateChatPanel(contact);
                    });
                }
            }, "ClientThread-" + contact.ip + ":" + contact.port).start();
        }
    }

    private void validateAndAddContact() {
        String ip = peerIpInout.getText().trim();
        String portStr = peerPortInput.getText().trim();

        if (ip.isEmpty() || portStr.isEmpty()) {
            javax.swing.JOptionPane.showMessageDialog(addPeerDialog, "Please fill in all fields.", "Input Error", javax.swing.JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (!isValidIpAddress(ip)) {
            javax.swing.JOptionPane.showMessageDialog(addPeerDialog, "Invalid IP Address format.", "Input Error", javax.swing.JOptionPane.ERROR_MESSAGE);
            return;
        }

        int port;
        try {
            port = Integer.parseInt(portStr);
            if (port < 1 || port > 65535) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException e) {
            javax.swing.JOptionPane.showMessageDialog(addPeerDialog, "Invalid Port. Please enter a number between 1 and 65535.", "Input Error", javax.swing.JOptionPane.ERROR_MESSAGE);
            return;
        }

        ActiveContact newContact = new ActiveContact(ip, port);
        contacts.add(newContact);

        addPeerDialog.setVisible(false);
        peerIpInout.setText("");
        peerPortInput.setText("");

        updateContactList();
    }

    public void onMessageReceived(String message, String ip) {
        for (ActiveContact contact : contacts) {
            if (contact.ip.equals(ip)) {
                contact.messages.add("peer- " + message);
                if (contact == selectedContact) {
                    SwingUtilities.invokeLater(() -> updateChatPanel(contact));
                }
                break;
            }
        }
    }

    public void onClientConnected(String ip, int port) {
        SwingUtilities.invokeLater(() -> {
            for (ActiveContact contact : contacts) {
                if (contact.ip.equals(ip) && contact.port == port) {
                    return;
                }
            }
            ActiveContact newContact = new ActiveContact(ip, port);
            contacts.add(newContact);
            updateContactList();
        });
    }

    public static void main(String args[]) {
        MessengerFrame frame = new MessengerFrame();

        java.awt.EventQueue.invokeLater(() -> {
            frame.setVisible(true);
        });

        SERVER_PORT = findFreePort(SERVER_IP, SERVER_PORT);
        new Thread(() -> startServer(SERVER_IP, SERVER_PORT, frame), "ServerThread").start();
    }
}
