import datetime
import json
import math
import multiprocessing
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from logging.handlers import RotatingFileHandler
import pythoncom
import socketio
from flask import Flask, render_template, request, send_from_directory, abort, redirect, url_for, session, jsonify
import os
import platform
import psutil
import win32com.client  # for WMI

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy

from nmap import nmap
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import Unauthorized
from apscheduler.schedulers.background import BackgroundScheduler
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
app.secret_key = 'HAROUNA'


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    pythoncom.CoInitialize()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        host = request.form['host']
        # Enregistrer les identifiants dans la session
        session['username'] = username
        session['password'] = password
        session['host'] = host
        return redirect(url_for('index'))
    return render_template('login.html')


def get_wmi_connection(host, username, password):
    pythoncom.CoInitialize()
    try:
        locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        connection = locator.ConnectServer(host, "root\\cimv2", username, password)
        return connection
    except Exception as e:
        error_message = str(e)
        if 'Access denied' in error_message:
            error_message = "Access denied. Check WMI and DCOM permissions and firewall settings on the remote machine."
        elif 'RPC server is unavailable' in error_message or 'Le serveur RPC n’est pas disponible' in error_message:
            error_message = "The RPC server is unavailable. Ensure that the RPC service is running on the remote machine."
        return redirect(url_for('error_page', error_message=error_message))

# Route to display error messages
@app.route('/error')
def error_page():
    error_message = request.args.get('error_message', 'An unknown error occurred')
    return render_template('eror.html', error_message=error_message)


def get_drives():
    drives = []
    if platform.system() == 'Windows':
        try:
            connection = get_wmi_connection(session['host'], session['username'], session['password'])
            for disk in connection.ExecQuery("SELECT * FROM Win32_LogicalDisk"):
                if disk.DriveType in [2, 3]:  # 2 pour les lecteurs amovibles, 3 pour les disques locaux
                    drives.append(disk.DeviceID + '\\')
        except Exception as e:
            print(f"Échec de l'obtention des unités de stockage : {e}")
            drives = None
    else:
        drives.append('/')
    return drives

def get_drive_info(connection, drive):
    try:
        for disk in connection.ExecQuery(f"SELECT * FROM Win32_LogicalDisk WHERE DeviceID = '{drive[0]}:'"):
            total = int(disk.Size)
            free = int(disk.FreeSpace)
            used = total - free
            percent = (used / total) * 100
            return {'total': total, 'used': used, 'free': free, 'percent': percent}
    except Exception as e:
        print(f"Échec de l'obtention des informations sur l'unité de stockage : {e}")
        return None
    else:
        usage = psutil.disk_usage(drive)
        return {
            'total': usage.total,
            'used': usage.used,
            'free': usage.free,
            'percent': usage.percent
        }


def safe_join(base, path):
    if base == 'root':
        final_path = path
    else:
        final_path = os.path.normpath(os.path.join(base, path))
    return final_path

@app.route('/', methods=['GET', 'POST'])
def index():
    pythoncom.CoInitialize()
    try:
        if 'username' not in session or 'password' not in session or 'host' not in session:
            return redirect(url_for('login_page'))

        username = session['username']
        password = session['password']
        host = session['host']

        base = request.args.get('base', 'root')
        path = request.args.get('path', '')

        connection = get_wmi_connection(host, username, password)

        if base == 'root':
            drives = get_drives()
            drive_info = {drive: get_drive_info(connection, drive) for drive in drives}
            common_dirs = {
                'Desktop': os.path.join(os.path.expanduser('~'), 'Desktop'),
                'Téléchargements': os.path.join(os.path.expanduser('~'), 'Downloads'),
                'Musique': os.path.join(os.path.expanduser('~'), 'Music'),
                'Documents': os.path.join(os.path.expanduser('~'), 'Documents')
            }

            cpu_usage = get_cpu_usage()
            ram_usage = get_ram_usage()
            network_data = get_network_adapters()
            return render_template('index.html', drives=drives, drive_info=drive_info, common_dirs=common_dirs,
                                   cpu_usage=cpu_usage, ram_usage=ram_usage, network_data=network_data)

        abs_path = safe_join(base, path)

        if abs_path is None:
            return render_template('error.html', error_message='Invalid or non-existent file path.')

        files = []

        # Requête pour les répertoires
        dir_query = "SELECT Name FROM Win32_Directory WHERE Drive='{}' AND Path='{}\\\\'".format(base[0] + ':', path.replace('/', '\\\\'))
        for item in connection.ExecQuery(dir_query):
            dir_name = item.Name.split('\\')[-1]  # Obtenez uniquement le nom du répertoire
            files.append({'name': dir_name, 'is_dir': True})

        # Requête pour les fichiers
        file_query = "SELECT Name, FileName, Extension FROM CIM_DataFile WHERE Drive='{}' AND Path='{}\\\\'".format(base[0] + ':', path.replace('/', '\\\\'))
        for item in connection.ExecQuery(file_query):
            file_name = "{}.{}".format(item.FileName, item.Extension)
            files.append({'name': file_name, 'is_dir': False})

        parent_dir = os.path.dirname(path) if path else ''
        display_mode = session.get('display_mode', 'grid')
        return render_template('index.html', files=files, current_path=path, parent_dir=parent_dir, base=base,
                               display_mode=display_mode)
    except PermissionError as er:
        return render_template('eror.html', error_message=str(er))
    except Exception as e:
        return render_template('eror.html', error_message=str(e))
    finally:
        pythoncom.CoUninitialize()

@app.route('/view')
def view_file():
    if 'username' not in session or 'password' not in session or 'host' not in session:
        return redirect(url_for('login_page'))

    username = session['username']
    password = session['password']
    host = session['host']

    base = request.values.get('base')
    path = request.values.get('path')

    if not base or not path:
        return abort(400, "Base or path is missing")

    abs_path = safe_join(base, path)
    if abs_path is None or not os.path.isfile(abs_path):
        return abort(404)

    try:
        with open(abs_path, 'r') as file:
            content = file.read()
    except Exception as e:
        return abort(500, f"Error reading file: {e}")

    return render_template('view_file.html', base=base, path=path, content=content)

def get_cpu_usage():
    try:
        # Récupérer les informations d'identification de l'ordinateur distant à partir de la session
        host = session['host']
        username = session['username']
        password = session['password']

        # Établir une connexion WMI
        connection = wmi.WMI(computer=host, user=username, password=password)
        for processor in connection.Win32_Processor():
            print(processor.Name)
        # Exécuter la requête WMI pour récupérer les informations sur le processeur
        cpu_info = connection.query("SELECT Name, LoadPercentage FROM Win32_Processor")

        if cpu_info:
            # Récupérer le nom du processeur et les charges de chaque cœur
            cpu_name = cpu_info[0].Name
            cpu_loads = [int(cpu.LoadPercentage) for cpu in cpu_info if cpu.LoadPercentage is not None]
        else:
            print("Échec de la récupération des informations sur le CPU depuis WMI.")
        # Utiliser psutil comme solution de secours si WMI échoue
        cpu_load = psutil.cpu_percent(interval=1)
        print(f"Charge CPU (psutil) : {cpu_load}%")
        return cpu_load
    except Exception as e:
        error_message = f"Échec de la récupération des informations sur le CPU : {e}"
        print(error_message)
        raise Exception(error_message)

def get_ram_usage():
    try:
        connection = get_wmi_connection(session['host'], session['username'], session['password'])
        cs = connection.ExecQuery("SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem")[0]
        total = int(cs.TotalVisibleMemorySize)
        free = int(cs.FreePhysicalMemory)
        used = total - free
        percent = (used / total) * 100
        return int(percent)  # Convertir le pourcentage en nombre entier
    except Exception as e:
        print(f"Échec de l'obtention de l'utilisation de la RAM : {e}")
        return None

@app.route('/copy_file', methods=['POST'])
def copy_file():
    if 'username' not in session or 'password' not in session or 'host' not in session:
        return jsonify({'error': 'Non autorisé'}), 401

    file_path = request.form.get('filePath')
    if file_path:
        session['copied_file'] = file_path
        return jsonify({'status': 'Fichier copié'}), 200
    else:
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400

@app.route('/cut_file', methods=['POST'])
def cut_file():
    if 'username' not in session or 'password' not in session or 'host' not in session:
        return jsonify({'error': 'Non autorisé'}), 401

    file_path = request.form.get('filePath')
    if file_path:
        session['cut_file'] = file_path
        return jsonify({'status': 'Fichier coupé'}), 200
    else:
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400

@app.route('/paste_file', methods=['POST'])
def paste_file():
    if 'username' not in session or 'password' not in session or 'host' not in session:
        return jsonify({'error': 'Non autorisé'}), 401

    base = request.form.get('base')
    current_path = request.form.get('currentPath')
    abs_path = safe_join(base, current_path)

    if 'copied_file' in session:
        copied_file = session['copied_file']
        if copied_file == abs_path:
            return jsonify({'error': 'Vous ne pouvez pas coller un fichier dans le même dossier.'}), 400
        else:
            # Implémenter la fonctionnalité de copier/coller
            print(f'Collage du fichier: {copied_file} vers {abs_path}')
            session.pop('copied_file')
            return jsonify({'status': 'Fichier collé'}), 200
    elif 'cut_file' in session:
        cut_file = session['cut_file']
        if cut_file == abs_path:
            return jsonify({'error': 'Vous ne pouvez pas déplacer un fichier dans le même dossier.'}), 400
        else:
            # Implémenter la fonctionnalité de couper/coller
            print(f'Déplacement du fichier: {cut_file} vers {abs_path}')
            session.pop('cut_file')
            return jsonify({'status': 'Fichier déplacé'}), 200
    else:
        return jsonify({'error': 'Aucun fichier n\'a été copié ou coupé.'}), 400

@app.route('/rename_file', methods=['POST'])
def rename_file():
    if 'username' not in session or 'password' not in session or 'host' not in session:
        return jsonify({'error': 'Non autorisé'}), 401

    base = request.form.get('base')
    current_path = request.form.get('currentPath')
    file_name = request.form.get('fileName')
    new_name = request.form.get('newName')

    abs_path = safe_join(base, current_path)
    if abs_path is None or not os.path.exists(abs_path):
        return jsonify({'error': 'Chemin de fichier invalide'}), 400

    if new_name and new_name != file_name:
        new_file_path = os.path.join(abs_path, new_name)
        try:
            os.rename(os.path.join(abs_path, file_name), new_file_path)
            return jsonify({'status': 'Fichier renommé', 'newPath': new_file_path}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Nouveau nom de fichier non valide'}), 400

@app.route('/change_display_mode', methods=['POST'])
def change_display_mode():
    if 'username' not in session or 'password' not in session or 'host' not in session:
        return jsonify({'error': 'Non autorisé'}), 401

    new_mode = request.form.get('mode')
    if new_mode in ['grid', 'list', 'icons']:
        session['display_mode'] = new_mode
        return jsonify({'status': 'Mode d\'affichage modifié', 'mode': new_mode}), 200
    else:
        return jsonify({'error': 'Mode d\'affichage invalide'}), 400

@app.route('/delete_file', methods=['POST'])
def delete_file():
    if 'username' not in session or 'password' not in session or 'host' not in session:
        return jsonify({'error': 'Non autorisé'}), 401

    file_path = request.form.get('filePath')
    print(f"Chemin de fichier reçu : {file_path}")

    if file_path:
        # Normaliser le chemin du fichier pour éviter les traversées de répertoires
        file_path = os.path.normpath(file_path)
        print(f"Chemin de fichier normalisé : {file_path}")

        # Vérifier si le fichier existe
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                return jsonify({'status': 'Fichier supprimé'}), 200
            except Exception as e:
                print(f"Erreur lors de la suppression du fichier : {str(e)}")
                return jsonify({'error': str(e)}), 500
        else:
            print(f"Le fichier n'existe pas à ce chemin : {file_path}")
            return jsonify({'error': 'Chemin de fichier invalide ou fichier non trouvé'}), 400
    else:
        print("Aucun chemin de fichier fourni.")
        return jsonify({'error': 'Chemin de fichier non fourni'}), 400

def get_wmi_connection(host, username, password):
    try:
        return wmi.WMI(host, user=username, password=password)
    except wmi.x_wmi as e:
        print(f"Error connecting to WMI: {e}")
        raise
import wmi

def get_wmi_connection(host, username, password):
    try:
        # Create a WMI connection with the specified credentials
        connection = wmi.WMI(
            computer=host,
            user=username,
            password=password,
            namespace='root\\cimv2',
        )
        return connection
    except Exception as e:
        print(f"Failed to connect to WMI: {e}")
        return None

def get_network_adapters():
    pythoncom.CoInitialize()
    try:
        if 'username' not in session or 'password' not in session or 'host' not in session:
            return redirect(url_for('login_page'))

        username = session['username']
        password = session['password']
        host = session['host']

        connection = get_wmi_connection(host, username, password)
        if not connection:
            print("Failed to establish WMI connection.")
            return None

        adapters = connection.Win32_NetworkAdapterConfiguration(IPEnabled=True)
        nics = connection.Win32_NetworkAdapter()
        if not adapters or not nics:
            print("No network adapters or NICs found.")
            return None

        perf_data = connection.Win32_PerfFormattedData_Tcpip_NetworkInterface()
        perf_data_available = bool(perf_data)

        network_data = []
        for adapter in adapters:
            print(f"Processing adapter: {adapter.Description}")
            nic = next((n for n in nics if n.Index == adapter.Index), None)

            if not nic:
                print(f"No matching NIC config found for adapter: {adapter.Description}")
                continue

            data = {
                'name': adapter.Description,
                'mac_address': adapter.MACAddress,
                'speed': getattr(nic, 'Speed', None),
                'status': getattr(nic, 'NetEnabled', None),
                'ip_address': adapter.IPAddress[0] if adapter.IPAddress else None,
                'subnet_mask': adapter.IPSubnet[0] if adapter.IPSubnet else None,
                'default_gateway': adapter.DefaultIPGateway[0] if adapter.DefaultIPGateway else None,
            }

            if perf_data_available:
                perf = next((p for p in perf_data if p.Name == adapter.Description or
                              (hasattr(p, 'MACAddress') and p.MACAddress == adapter.MACAddress)), None)
                if perf:
                    data['bytes_received'] = getattr(perf, 'BytesReceivedPerSec', None)
                    data['bytes_sent'] = getattr(perf, 'BytesSentPerSec', None)
                    data['packets_received'] = getattr(perf, 'PacketsReceivedPerSec', None)
                    data['packets_sent'] = getattr(perf, 'PacketsSentPerSec', None)
                else:
                    print(f"No performance data found for adapter: {adapter.Description}")

            print(f"Adapter data: {data}")
            network_data.append(data)

        print(f"Final network data: {network_data}")
        return network_data

    except Exception as e:
        print(f'Error: {e}')
        return None
    finally:
        pythoncom.CoUninitialize()


@app.route('/usage')
def usage():
    pythoncom.CoInitialize()
    cpu_usage = get_cpu_usage()
    ram_usage = get_ram_usage()
    network_data = get_network_adapters()
    return jsonify({'cpu_usage': cpu_usage, 'ram_usage': ram_usage,'network_data': network_data})




@app.template_filter('convert_bytes')
def convert_bytes(value):
    for unit in ['o', 'Ko', 'Mo', 'Ho', 'To', 'Po', 'Eo', 'Zo']:
        if value < 1024:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} Yo"

# Configuration de la journalisation
logging.basicConfig(level=logging.DEBUG)


# Fonction pour parser la date et l'heure WMI
logging.basicConfig(level=logging.INFO)

def get_wmi_connection(host, username, password):
    try:
        wmi = win32com.client.GetObject(f"\\\\{host}\\root\\cimv2")
        wmi.Security_.ImpersonationLevel = 3  # WMI_ImpersonationLevel_Impersonate
        wmi.Security_.AuthenticationLevel = 6  # WMI_AuthenticationLevel_PacketPrivacy
        return wmi
    except Exception as e:
        logging.error(f"Erreur de connexion WMI : {str(e)}")
        raise e

def parse_wmi_datetime(wmi_date_str):
    date_part = wmi_date_str.split('.')[0]
    microseconds = int(wmi_date_str.split('.')[1][:-4])
    return datetime.datetime.strptime(date_part, '%Y%m%d%H%M%S') + datetime.timedelta(microseconds=microseconds)

def check_system_update(connection):
    try:
        wmiClasses1 = connection.ExecQuery("SELECT * FROM Win32_OperatingSystem")
        lastWindowsUpdateDate = None
        for wmiClass in wmiClasses1:
            lastWindowsUpdateDate = parse_wmi_datetime(wmiClass.LastBootUpTime)

        currentDateTime = datetime.datetime.now()
        update_threshold = datetime.timedelta(days=7)

        update_session = win32com.client.Dispatch("Microsoft.Update.Session")
        searcher = update_session.CreateUpdateSearcher()
        search_result = searcher.Search("IsInstalled=0")
        updates_available = search_result.Updates.Count > 0

        windows_up_to_date = (currentDateTime - lastWindowsUpdateDate <= update_threshold) and (not updates_available)

        return {
            'up_to_date': windows_up_to_date,
            'last_update_date': lastWindowsUpdateDate.strftime('%Y-%m-%d %H:%M:%S'),
            'updates_available': updates_available
        }
    except Exception as e:
        error_message = f"Erreur WMI : {e}"
        logging.error(error_message)
        return {'error': error_message}

@app.route('/update_status')
def update_status():
    try:
        if 'username' not in session or 'password' not in session or 'host' not in session:
            return jsonify({'error': 'Informations de connexion manquantes'}), 401

        host = session['host']
        username = session['username']
        password = session['password']

        connection = get_wmi_connection(host, username, password)
        update_status = check_system_update(connection)

        return jsonify(update_status)
    except Exception as e:
        logging.error(f"Erreur lors de la récupération de l'état de mise à jour : {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/update_system', methods=['POST'])
def update_system():
    pythoncom.CoInitialize()
    try:
        if 'username' not in session or 'password' not in session or 'host' not in session:
            return jsonify({'error': 'Non autorisé'}), 401

        host = session['host']
        username = session['username']
        password = session['password']

        connection = get_wmi_connection(host, username, password)
        logging.info(f"Connexion WMI établie avec {host}")

        update_session = win32com.client.Dispatch("Microsoft.Update.Session")
        searcher = update_session.CreateUpdateSearcher()
        search_result = searcher.Search("IsInstalled=0")
        updates_available = search_result.Updates
        logging.info(f"{updates_available.Count} mises à jour disponibles trouvées")

        download_collection = win32com.client.Dispatch("Microsoft.Update.UpdateColl")
        for update in updates_available:
            try:
                is_downloaded = getattr(update, 'IsDownloaded', False)
                if not is_downloaded:
                    download_collection.Add(update)
            except Exception as e:
                logging.error(f"Erreur lors de la vérification de l'attribut 'IsDownloaded' pour une mise à jour : {str(e)}")

        if download_collection.Count == 0:
            logging.info("Aucune mise à jour à télécharger")
            return jsonify({'status': 'Aucune mise à jour disponible'}), 200

        downloader = win32com.client.Dispatch("Microsoft.Update.Downloader")
        downloader.ClientApplicationID = "My Update Client"
        downloader.Download(download_collection)

        installer = win32com.client.Dispatch("Microsoft.Update.Installer")
        installation_result = installer.Install(download_collection)

        if installation_result.RebootRequired:
            logging.info("Une redémarrage est nécessaire pour terminer la mise à jour")
            return jsonify({'status': 'Redémarrage requis'}), 200
        else:
            logging.info("Mise à jour terminée avec succès")
            return jsonify({'status': 'Mise à jour terminée'}), 200

    except Exception as e:
        logging.error(f"Erreur lors de la mise à jour du système : {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        pythoncom.CoUninitialize()

# Route for shutting down the system
def get_wmi_connection(host, username, password):
    pythoncom.CoInitialize()
    connection = wmi.WMI(computer=host, user=username, password=password)
    return connection

@app.route('/shutdown', methods=['POST'])
def shutdown_system():
    try:
        if 'username' not in session or 'password' not in session or 'host' not in session:
            raise Unauthorized("Informations de connexion manquantes.")

        connection = get_wmi_connection(session['host'], session['username'], session['password'])

        os = connection.Win32_OperatingSystem(Primary=True)[0]
        os.Shutdown()

        return jsonify({'status': 'Le système est en cours darrêt'}), 200

    except Unauthorized as e:
        return redirect(url_for('error_page', error_message=str(e)))
    except Exception as e:
        error_message = str(e)
        if 'Access denied' in error_message:
            error_message = "Accès refusé. Vérifiez les autorisations WMI et DCOM, ainsi que les paramètres du pare-feu sur la machine distante."
        elif 'RPC server is unavailable' in error_message or 'Le serveur RPC nest pas disponible' in error_message:
            error_message = "Le serveur RPC n'est pas disponible. Assurez-vous que le service RPC est en cours d'exécution sur la machine distante."
        return redirect(url_for('error_page', error_message=error_message))
    finally:
        pythoncom.CoUninitialize()

@app.route('/restart', methods=['POST'])
def restart_system():
    try:
        if 'username' not in session or 'password' not in session or 'host' not in session:
            raise Unauthorized("Informations de connexion manquantes.")

        connection = get_wmi_connection(session['host'], session['username'], session['password'])

        os = connection.Win32_OperatingSystem(Primary=True)[0]
        os.Reboot()

        return jsonify({'status': 'Le système est en cours de redémarrage'}), 200

    except Unauthorized as e:
        return redirect(url_for('error_page', error_message=str(e)))
    except Exception as e:
        error_message = str(e)
        if 'Access denied' in error_message:
            error_message = "Accès refusé. Vérifiez les autorisations WMI et DCOM, ainsi que les paramètres du pare-feu sur la machine distante."
        elif 'RPC server is unavailable' in error_message or 'Le serveur RPC nest pas disponible' in error_message:
            error_message = "Le serveur RPC n'est pas disponible. Assurez-vous que le service RPC est en cours d'exécution sur la machine distante."
        return redirect(url_for('error_page', error_message=error_message))
    finally:
        pythoncom.CoUninitialize()


# Example route to set session information (host, username, password)
@app.route('/set_session', methods=['POST'])
def set_session():
    data = request.get_json()
    session['host'] = data.get('host')
    session['username'] = data.get('username')
    session['password'] = data.get('password')
    return jsonify({'status': 'Session information set'}), 200

@app.route('/check_host_accessibility', methods=['GET'])
def check_host_accessibility():
    host = session.get('host')
    if host:
        # Here you can perform a check to see if the host is accessible
        # For simplicity, let's assume a basic check
        import socket
        socket.setdefaulttimeout(1)  # Set timeout for 1 second
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, 80))
            return jsonify({'status': 'accessible'}), 200
        except Exception as e:
            return jsonify({'status': 'not_accessible', 'error': str(e)}), 200
    else:
        return jsonify({'status': 'host_not_set'}), 400
# Example route to clear session information
@app.route('/clear_session', methods=['POST'])
def clear_session():
    session.clear()
    return jsonify({'status': 'Session information cleared'}), 200

# Route de téléchargement de fichier
@app.route('/download')
def download():
    try:

        if 'username' not in session or 'password' not in session or 'host' not in session:
            return redirect(url_for('login_page'))

        username = session['username']
        password = session['password']
        host = session['host']

        base = request.args.get('base', 'root')
        path = request.args.get('path', '')

        abs_path = safe_join(base, path)
        if abs_path is None or not os.path.isfile(abs_path):
            return abort(404)

        directory = os.path.dirname(abs_path)
        filename = os.path.basename(abs_path)
        return send_from_directory(directory, filename, as_attachment=True)
    except PermissionError as er:
        return render_template('eror.html', error_message=str(er))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/get_events', methods=["POST"])
def get_events():
    pythoncom.CoInitialize()
    try:
        logging.info('Début de la fonction get_events')

        username = session.get('username')
        password = session.get('password')
        host = session.get('host')
        event_log = request.form.get('event_type')

        logging.info(f'Paramètres reçus : computer={host}, username={username}, event_log={event_log}')

        if event_log not in ['security', 'system', 'application','setup','forwardedEvents']:
            logging.warning(f'Type d\'événement non valide : {event_log}')
            return jsonify({'error': 'Evènement non valide ou indisponible.'})

        c = wmi.WMI(computer=host, user=username, password=password)
        logging.info('Connexion WMI établie')

        query = f"SELECT * FROM Win32_NTLogEvent WHERE LogFile='{event_log}'"
        events = c.ExecQuery(query)
        logging.info(f'Requête WMI exécutée : {query}')

        recent_events = []
        for i, event in enumerate(events):
            if i >= 10:
                break

            status = {
                0: "Success",
                1: "Error",
                2: "Warning",
                4: "Security audit success",
                5: "Security audit failure"
            }.get(event.EventType, "Information")

            recent_events.append({
                'EventType': event.EventType,
                'Message': event.Message,
                'TimeGenerated': str(event.TimeGenerated),
                'SourceName': event.SourceName,
                'User': event.User,
                'Status': status,
                'ComputerName': event.ComputerName,
            })

        logging.info(f'{len(recent_events)} événements récupérés')
        return jsonify({'recent_events': recent_events, 'event_log': event_log})

    except Exception as e:
        logging.error(f'Erreur dans get_events : {str(e)}')
        return jsonify({'error': 'Erreur de traitement de la requête.'})
    finally:
        pythoncom.CoUninitialize()
        logging.info('Fin de la fonction get_events')

socketio = SocketIO(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

DEFAULT_SCAN_OPTIONS = '-O -T4'

# Charger la carte OS à partir du JSON
base_dir = os.path.abspath(os.path.dirname(__file__))
json_file_path = os.path.join(base_dir, 'os_map.json')

with open(json_file_path, 'r') as f:
    DETAILED_OS_MAP = json.load(f)


@app.route('/network_scan_page')
@limiter.limit("10 per minute")
def network_scan_page():
    return render_template('network_scan.html')


@socketio.on('start_scan')
def handle_start_scan(data):
    global scanning
    if scanning:
        return  # Ignorer les nouvelles demandes si un scan est déjà en cours

    network_range = data.get('network_range')
    scan_options = data.get('scan_options', DEFAULT_SCAN_OPTIONS)
    socketio.emit('scan_started')
    # Assurer que scan_network n'est pas bloquant
    socketio.start_background_task(scan_network, network_range, scan_options)


@socketio.on('stop_scan')
def handle_stop_scan():
    global scanning
    scanning = False


def scan_ip(ip, scan_options):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments=scan_options)
        if ip in nm.all_hosts():
            host_info = nm[ip]
            os_info = 'Unknown'
            if 'osmatch' in host_info and host_info['osmatch']:
                os_match = host_info['osmatch'][0]
                os_info = os_match['name']
            detailed_os = get_detailed_os_name(os_info)
            return {
                'ip': ip,
                'status': host_info['status']['state'],
                'hostnames': [hostname['name'] for hostname in host_info.get('hostnames', [])],
                'os': detailed_os
            }
    except Exception as e:
        app.logger.error(f"Error scanning IP {ip}: {e}")
    return None


# Flag pour contrôler le scan
scanning = False


def scan_network(network_range, scan_options):
    global scanning
    scanning = True
    max_workers = min(20, multiprocessing.cpu_count())  # réduire à un nombre optimal de threads
    total_ips = 254  # Supposons un réseau de classe /24

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_ip, f"{network_range}.{i}", scan_options) for i in range(1, 255)]

        for i, future in enumerate(futures):
            if not scanning:  # Vérifier si le scan doit être arrêté
                break

            result = future.result()
            if result:
                socketio.emit('host_found', result)

            # Émettre périodiquement pour réduire les émissions socket.io
            if i % 10 == 0 or i == total_ips - 1:
                progress_percentage = math.floor(((i + 1) / total_ips) * 100)
                socketio.emit('progress', {'progress': progress_percentage, 'status': 'Scanning...'})

                # Arrêter le scan si 100 % atteint
                if progress_percentage >= 100:
                    break

    if scanning:  # Vérifier si le scan n'était pas arrêté manuellement
        socketio.emit('progress', {'progress': 100, 'status': 'Scan completed'})

    # Réinitialiser le flag de scanning
    scanning = False


# Cache simple pour les noms détaillés des OS
os_cache = {}


def get_detailed_os_name(os_name):
    os_name_lower = os_name.lower()
    if os_name_lower in os_cache:
        return os_cache[os_name_lower]

    detailed_name = DETAILED_OS_MAP.get(os_name_lower, os_name.capitalize() if os_name != 'Unknown' else 'Unknown')
    os_cache[os_name_lower] = detailed_name
    return detailed_name

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))
if __name__ == '__main__':
    # Set up logging
    if not os.path.exists('logs'):
        os.makedirs('logs')
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    allow_unsafe_werkzeug = True
    app.wsgi_app = ProxyFix(app.wsgi_app)
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)