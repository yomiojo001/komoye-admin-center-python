# Komoye Admin Center - Python
## KOMOYE ADMIN CENTER (KAC) is a Python Flask app for efficient management and monitoring of network devices, enhancing IT operation

![Komoye Admin Center - Python](https://www.codester.com/static/uploads/items/000/051/51602/preview-xl.jpg)

## Overview
Hello and welcome! Today, I am excited to introduce our remote management application, an innovative solution that revolutionizes the way you interact with your Windows systems. With a unique combination of advanced features, our application transforms your approach to IT management by offering unprecedented flexibility, efficiency, and responsiveness.

## A Revolution in IT Management
Imagine being able to manage your Windows systems in real-time without disrupting local users' work. Our application allows you to connect remotely while giving them the freedom to continue their activities. You can monitor performance, access system resources, and troubleshoot issues without ever interrupting their workflow.


## Features


- **Seamless Connection:** One of the main advantages of our application is its ability to connect to Windows machines without disconnecting the local user. Unlike traditional remote desktop systems, which often require locking or disconnecting the current session, our application allows you to monitor and manage resources in real-time while letting the user work uninterrupted. This fosters smooth collaboration and ensures that daily operations are not disrupted.
- **Remote Shutdown and Restart Functionality:** Easily shut down or restart remote machines as needed, providing you with full control over your systems.
- **Simplified Access to System Resources:** With our application, you have direct and simplified access to essential information from the remote machine. You can monitor CPU, RAM, and network usage all from an intuitive web interface, enabling you to make informed decisions quickly without navigating through complex graphical interfaces.
- **Efficient File Management:**  Our application offers powerful file management capabilities. You can easily copy, cut, paste, rename, and delete files on the remote machine without needing an RDP connection. This allows for straightforward file management even when the local user is active.
- **Proactive Performance Monitoring:** Real-time monitoring of system performance is essential for maintaining a healthy IT environment. With our application, you can access CPU and RAM usage statistics, identify bottlenecks, and act quickly to optimize performance. This allows you to anticipate problems before they affect productivity.
- **Remote Update Management:** Keep your systems updated effortlessly. Our application allows you to check and install Windows updates remotely, ensuring that your machines are protected against vulnerabilities. This greatly simplifies the update management process, allowing you to focus on more strategic tasks.
- **Intuitive User Interface:** We designed our application with the user in mind. The web interface is intuitive and easy to navigate, meaning even non-technical users can quickly adapt and take advantage of all the offered features. This reduces training time and increases your team's efficiency.
- **Flexibility and Lightweight:** Unlike remote desktop solutions that can be resource-intensive, our application uses lightweight protocols to access system data. This reduces the load on your network and improves application responsiveness, even in low-bandwidth environments.
- **Real-Time Network Management:** An essential feature of our application is its ability to scan and detect connected hosts on local and remote networks in real-time. You can visualize all connected devices, identify new hosts, and continuously monitor their status. This feature allows you to keep an eye on your network infrastructure and respond quickly if suspicious behavior or connectivity issues are detected.


## Requirements
Before proceeding with the installation, please ensure that you meet the following prerequisites:

- **Python 3.x:** Download and install Python from the official website: https://www.python.org/downloads/. Ensure that you check the option to add Python to your PATH during installation.
- **Python Libraries:** After installing Python, open your command prompt (CMD) and run the following command to install the necessary libraries:
```bash
pip install Flask Flask-SocketIO Flask-Limiter pythoncom psutil nmap wmi
```
- **Administrator Access:** You will need administrative rights to access WMI on remote machines. Make sure you are logged in as an administrator or have the necessary permissions.


## Technical Prerequisites
- **Operating System:** Windows is required for the installation and operation of the Remote Management Application, specifically for accessing Windows Management Instrumentation (WMI). WMI is a core component of Windows operating systems that provides a standardized way to access management information in an enterprise environment. The following versions of Windows are supported:
    - Windows 10
    - Windows 11
    - Windows Server 2016
    - Windows Server 2019
    - Windows Server 2022
Ensure that your system is updated to the latest service pack and updates for optimal performance and security.
- **Listening Port:** ###/strongcode###5000. To ensure that your application can communicate over the network, follow these steps:
- **Open Windows Firewall:** Go to the Start menu, type Windows Defender Firewall, and press Enter.


## Instructions
1. **Download the Application:** After purchasing the application, you will receive a download link via email or from your account on the website where you made the purchase. Click on the link to download the application package, which is typically in a .zip or .tar.gz format.
2. **Extract the Files:** Once the download is complete, locate the downloaded file and extract its contents to a directory of your choice. You can do this by right-clicking on the file and selecting the "Extract" option (e.g., "Extract All" in Windows or using a command like `tar -xvzf your_file.tar.gz` in Linux). This will create a folder containing the application files.
- **Navigate to the Application Directory:** Open your command prompt or terminal and change into the directory where the application files were extracted:
```bash
cd path/to/extracted_directory
```
Replace `path/to/extracted_directory` with the actual path where you extracted the application.
4. **Install Dependencies:** Ensure that all required dependencies are installed by running the following command:
```bash
pip install -r requirements.txt
```
If a `requirements.txt` file is not available, you should manually install the necessary Python libraries. The required libraries may include:
    - `Flask`
    - `Flask-SocketIO`
    - `Flask-Limiter`
    - `pythoncom`
    - `psutil`
    - `nmap`
    - `wmi`
You can install these libraries individually using the command:
```bash
pip install library_name
```
5. **Configuration:** Before launching the application, you may need to configure it to suit your environment. Locate the configuration file (often named `config.py` or similar) and modify the settings to adjust connection details such as IP addresses, ports, and any other parameters specific to your setup.
6. **Launch the Application:** Start the application by running the following command:
```bash
python app.py###/pre/li###
```
7. **Access the Application:** Open your web browser and navigate to:
```bash
http://localhost:5000###/pre/li###
```