runtimeAV is a shell script that automates the installation and configuration of ClamAV antivirus on Linux systems. It sets up real-time monitoring of all public_html directories inside the /home folder, scanning files immediately upon modification or addition to prevent the execution of malicious scripts or infected files.

Key features:

Automatic ClamAV installation and configuration
Real-time monitoring and scanning of public_html directories
Quarantine functionality for infected files
Detailed logging and status reporting
Automatic database updates
Integration with systemd for service management

To quickly install and run runtimeAV, use the following command:

INSTALLATION:

curl -sSL https://raw.githubusercontent.com/n3fquick/runtimeav/main/install.sh -o install.sh && chmod +x install.sh && sudo ./install.sh

Useful Commands:

run pm2 logs clamav-monitor to check logs for quarantined/monitored files.
(pm2 will be downloaded during installation as well as node, if  already installed will be skipped)
