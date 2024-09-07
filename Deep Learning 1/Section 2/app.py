import matplotlib
matplotlib.use('Agg')
from flask import Flask, request, render_template, url_for
from flask_mail import Mail, Message
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.animation as animation
from matplotlib.animation import PillowWriter
from datetime import timedelta
import os
from io import BytesIO

app = Flask(__name__)

# Configure Flask-Mail with your SMTP server settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'surethans.22msc@kongu.edu'
app.config['MAIL_PASSWORD'] = 'aqfg piro lmvs zbpf'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Define the attack types columns
attack_types = ['Spam', 'Ransomware', 'Local Infection', 'Exploit', 'Malicious Mail',
                'Network Attack', 'On Demand Scan', 'Web Threat']

# Load the data
file_path = 'cyber_data.csv'
cyber_data = pd.read_csv(file_path)
cyber_data['AttackDate'] = pd.to_datetime(cyber_data['AttackDate'], dayfirst=True)

# Attack descriptions and prevention techniques
attack_info = {
    'Spam': {
        'description': 'Spam involves sending unsolicited messages, typically in bulk, usually for advertising.',
        'prevention': [
            'Use advanced spam filters to automatically detect and block spam emails.',
            'Avoid clicking on links or downloading attachments from unknown or suspicious emails.',
            'Do not share your email address publicly or with untrusted sources.',
            'Regularly update your email software to protect against new spam techniques.',
            'Educate users about phishing and how to recognize spam emails.',
            'Use a secondary email address for online registrations and subscriptions.',
            'Enable multi-factor authentication (MFA) for email accounts.',
            'Report spam emails to your email provider to improve filtering.',
            'Avoid responding to spam emails, as this can confirm your address is active.',
            'Regularly check your email account for unauthorized forwarding rules or settings changes.'
        ]
    },
    'Ransomware': {
        'description': 'Ransomware is a type of malware that encrypts data, demanding ransom for decryption.',
        'prevention': [
            'Regularly back up your data and store backups offline or in a secure cloud service.',
            'Keep your operating system and software up to date with the latest security patches.',
            'Use antivirus software with real-time protection and regularly perform scans.',
            'Be cautious when opening email attachments or clicking on links from unknown senders.',
            'Disable macros in email attachments and Office files from untrusted sources.',
            'Limit user permissions to prevent the execution of unauthorized software.',
            'Implement network segmentation to restrict the spread of ransomware.',
            'Use email and web filters to block malicious content.',
            'Train employees to recognize phishing and social engineering attacks.',
            'Consider using endpoint detection and response (EDR) solutions for enhanced protection.'
        ]
    },
    'Local Infection': {
        'description': 'Local infection refers to malware that affects the local system, leading to unauthorized changes or data theft.',
        'prevention': [
            'Install and regularly update antivirus software to detect and remove malware.',
            'Avoid downloading software or files from untrusted websites or sources.',
            'Enable firewalls to block unauthorized access to your system.',
            'Keep your operating system and applications up to date with security patches.',
            'Disable auto-run features for external devices to prevent automatic malware execution.',
            'Be cautious when using removable media like USB drives; scan them for malware first.',
            'Use strong, unique passwords for all accounts and enable multi-factor authentication.',
            'Regularly review and manage installed programs to detect any unauthorized changes.',
            'Implement user access controls to limit the installation of unauthorized software.',
            'Educate users about safe browsing habits and the risks of downloading from unknown sources.'
        ]
    },
    'Exploit': {
        'description': 'An exploit takes advantage of a software vulnerability to gain unauthorized access or control over a system.',
        'prevention': [
            'Regularly update and patch all software, including operating systems and applications.',
            'Use intrusion detection and prevention systems (IDS/IPS) to monitor for exploit attempts.',
            'Limit user privileges to reduce the risk of exploit-based attacks.',
            'Implement application whitelisting to prevent unauthorized software execution.',
            'Conduct regular vulnerability assessments and penetration testing.',
            'Use a web application firewall (WAF) to protect against web-based exploits.',
            'Isolate critical systems from the internet and other less secure environments.',
            'Disable unnecessary services and ports to reduce the attack surface.',
            'Educate users about common exploit techniques, such as buffer overflow attacks.',
            'Use secure coding practices to minimize the introduction of vulnerabilities in software development.'
        ]
    },
    'Malicious Mail': {
        'description': 'Malicious mail contains harmful attachments or links that can compromise security when opened.',
        'prevention': [
            'Enable advanced email filtering to block malicious attachments and links.',
            'Train employees to recognize and report suspicious emails.',
            'Implement sandboxing to safely analyze email attachments before they reach users.',
            'Use email authentication protocols like SPF, DKIM, and DMARC to reduce email spoofing.',
            'Regularly update your email client and security software.',
            'Encourage users to verify the source of unexpected attachments or links.',
            'Disable automatic downloading of attachments in email clients.',
            'Use multi-factor authentication (MFA) to secure email accounts.',
            'Monitor email traffic for unusual activity that could indicate a compromise.',
            'Consider deploying an email security gateway to protect against advanced threats.'
        ]
    },
    'Network Attack': {
        'description': 'Network attacks target the infrastructure of a network, leading to disruptions or unauthorized access.',
        'prevention': [
            'Implement strong network security protocols, including encryption and VPNs.',
            'Use firewalls to filter incoming and outgoing network traffic.',
            'Regularly update network devices and software with security patches.',
            'Segment your network to isolate sensitive data and systems.',
            'Monitor network traffic for signs of intrusion or unusual activity.',
            'Implement access control lists (ACLs) to limit access to critical systems.',
            'Use network intrusion detection systems (NIDS) to detect and respond to attacks.',
            'Secure wireless networks with strong encryption, like WPA3.',
            'Limit physical access to network devices and infrastructure.',
            'Train employees to recognize social engineering tactics that could lead to network breaches.'
        ]
    },
    'On Demand Scan': {
        'description': 'On Demand Scans are initiated by users to detect and remove malware from systems.',
        'prevention': [
            'Regularly perform on-demand scans to identify and remove malware.',
            'Ensure your antivirus software is updated with the latest virus definitions.',
            'Schedule regular scans during off-hours to minimize disruption.',
            'Run full system scans periodically to detect deeply embedded threats.',
            'Use cloud-based scanning for real-time threat detection.',
            'Quarantine detected threats immediately to prevent further infection.',
            'Review scan logs to identify patterns or recurring threats.',
            'Educate users on how to initiate scans and interpret results.',
            'Use on-demand scans as a complement to real-time protection.',
            'Consider using multiple scanning engines to increase detection rates.'
        ]
    },
    'Web Threat': {
        'description': 'Web threats encompass a wide range of malicious activities or content encountered while browsing the internet, including phishing sites, drive-by downloads, and malicious ads.',
        'prevention': [
            'Use a secure web browser and keep it updated with the latest security patches.',
            'Install browser extensions that block malicious ads and phishing sites.',
            'Enable HTTPS-only mode to ensure secure communication with websites.',
            'Be cautious when clicking on links, especially in emails or on social media.',
            'Avoid downloading files from untrusted websites.',
            'Regularly clear your browser cache and cookies to remove potentially harmful data.',
            'Use a Virtual Private Network (VPN) for added privacy and security while browsing.',
            'Enable multi-factor authentication (MFA) for accounts accessed online.',
            'Educate users on recognizing and avoiding phishing attempts.',
            'Monitor web traffic for unusual activity or signs of compromise.'
        ]
    }
}


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/charts', methods=['GET'])
def charts():
    chart_type = request.args.get('type')
    country = request.args.get('country')

    if chart_type not in ['gantt', 'bar', 'time_series', 'time_series_animation']:
        return "Invalid chart type", 400
     
    if country not in cyber_data['Country'].unique():
        return "Invalid country", 400

    if chart_type == 'gantt':
        image = create_gantt_chart(country)
        extension = 'png'
    elif chart_type == 'bar':
        image = create_bar_chart(country)
        extension = 'png'
    elif chart_type == 'time_series':
        image = create_time_series_chart(country)
        extension = 'png'
    elif chart_type == 'time_series_animation':
        image = create_time_series_animation(country)
        extension = 'gif'

    image_name = f"{chart_type}_{country}.{extension}"
    image_path = os.path.join('static', image_name)
    with open(image_path, 'wb') as f:
        f.write(image.getvalue())

    return render_template('chart_display.html', chart_type=chart_type, country=country, chart_url=image_name)

def create_gantt_chart(country):
    country_data = cyber_data[cyber_data['Country'] == country]
    gantt_data = []

    for attack_type in attack_types:
        if not pd.isna(country_data[attack_type].values[0]):
            start_date = pd.to_datetime(country_data['AttackDate'].values[0])
            finish_date = start_date + timedelta(days=1)
            gantt_data.append((attack_type, start_date, finish_date))

    if not gantt_data:
        return None

    fig, ax = plt.subplots(figsize=(12, 8))
    for i, (task, start, finish) in enumerate(gantt_data):
        ax.barh(task, (finish - start).days, left=start, color='skyblue')

    ax.set_xlabel('Date')
    ax.set_title(f'Timeline of Different Attack Types in {country}')
    ax.xaxis_date()
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    plt.xticks(rotation=45)
    plt.tight_layout()

    buf = BytesIO()
    plt.savefig(buf, format='png')
    plt.close(fig)
    buf.seek(0)
    return buf

def create_bar_chart(country):
    country_data = cyber_data[cyber_data['Country'] == country]
    attack_counts = country_data[attack_types].sum()

    plt.figure(figsize=(12, 8))
    attack_counts.plot(kind='bar')

    plt.title(f'Number of Different Attack Types in {country}')
    plt.xlabel('Attack Type')
    plt.ylabel('Number of Attacks')
    plt.xticks(rotation=45)
    plt.tight_layout()

    buf = BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    buf.seek(0)
    return buf

def create_time_series_chart(country):
    country_data = cyber_data[cyber_data['Country'] == country]
    time_series_data = pd.DataFrame(index=country_data['AttackDate'].unique())

    for attack_type in attack_types:
        time_series_data[attack_type] = country_data.groupby('AttackDate')[attack_type].sum()

    plt.figure(figsize=(14, 8))
    for attack_type in attack_types:
        plt.plot(time_series_data.index, time_series_data[attack_type], label=attack_type)

    plt.title(f'Time Series of Different Attack Types in {country}')
    plt.xlabel('Date')
    plt.ylabel('Number of Attacks')
    plt.legend(title='Attack Types')
    plt.xticks(rotation=45)
    plt.tight_layout()

    buf = BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    buf.seek(0)
    return buf

def create_time_series_animation(country):
    country_data = cyber_data[cyber_data['Country'] == country]
    time_series_data = country_data.groupby(['AttackDate'])[attack_types].sum().reindex(
        pd.date_range(start=country_data['AttackDate'].min(), end=country_data['AttackDate'].max(), freq='D')
    ).fillna(0)

    fig, ax = plt.subplots(figsize=(14, 8))
    lines = [ax.plot([], [], label=attack_type)[0] for attack_type in attack_types]

    ax.set_xlim(time_series_data.index.min(), time_series_data.index.max())
    ax.set_ylim(0, time_series_data[attack_types].max().max())
    ax.set_title(f'Time Series of Different Attack Types in {country}')
    ax.set_xlabel('Date')
    ax.set_ylabel('Number of Attacks')
    ax.legend(title='Attack Types')
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    plt.xticks(rotation=45)

    def init():
        for line in lines:
            line.set_data([], [])
        return lines

    def update(frame):
        x = time_series_data.index[:frame]
        for i, attack_type in enumerate(attack_types):
            y = time_series_data[attack_type][:frame]
            lines[i].set_data(x, y)
        return lines

    ani = animation.FuncAnimation(fig, update, frames=len(time_series_data), init_func=init, blit=True, interval=50)
    temp_filename = 'temp_animation.gif'
    ani.save(temp_filename, writer=PillowWriter(fps=20))
    
    buf = BytesIO()
    with open(temp_filename, 'rb') as f:
        buf.write(f.read())
    buf.seek(0)
    
    os.remove(temp_filename)
    return buf

@app.route('/send_email', methods=['POST'])
def send_email():
    chart_url = request.form['chart_url']
    chart_type = request.form['chart_type']
    country = request.form['country']
    email = request.form['email']
    country_data = cyber_data[cyber_data['Country'] == country]
    attack_counts = country_data[attack_types].sum()
    most_frequent_attack = attack_counts.idxmax()
    attack_description = attack_info[most_frequent_attack]['description']
    prevention_technique = attack_info[most_frequent_attack]['prevention']

    msg = Message(f"{chart_type.capitalize()} Chart for {country}",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])

    msg.body = (f"The most frequent attack type in {country} is '{most_frequent_attack}'.\n\n"
                f"Description: {attack_description}\n"
                f"Prevention: {prevention_technique}\n\n"
                f"Please find the attached {chart_type} chart for more details.")

    mime_type = 'image/gif' if chart_url.endswith('.gif') else 'image/png'
    try:
        with open(os.path.join('static', chart_url), 'rb') as file:
            img_data = file.read()
            msg.attach(chart_url, mime_type, img_data)

        mail.send(msg)
        return "Email sent successfully!", 200
    except Exception as e:
        print(f"Failed to send email: {e}")
        return "Failed to send email", 500

if __name__ == '__main__':
    app.run(debug=True)