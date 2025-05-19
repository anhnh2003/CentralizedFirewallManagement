# -*- encoding: utf-8 -*-
from apps.home import blueprint
from apps import db
from flask import render_template, request, flash, redirect, url_for, redirect, jsonify
from flask_login import login_required, current_user
from jinja2 import TemplateNotFound
import subprocess, tempfile, os, stat
import re
import html
from collections import Counter
import logging
from apps.home.util import role_required
from apps.authentication.util import hash_pass
from apps.authentication.models import Users, Nodes, UserNodes
# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Log messages of level DEBUG and above
    format='%(asctime)s [%(levelname)s] %(message)s',  # Log message format
    handlers=[logging.StreamHandler()]  # Log to the console
)
@blueprint.route('/')
@login_required
def default():
    return render_template('home/index.html', segment='index')
@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500

# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
@blueprint.route('/input_status')
@login_required
def input_status():
    input_status = query_iptables('INPUT')
    #parse the output into a list of lists, where each inner list represents a row of the iptables output
    table_data = parse_iptables_output(input_status)
    return render_template('home/status.html', table_data=table_data, chain='INPUT')



@blueprint.route('/output_status')
@login_required
def output_status():
    output_status = query_iptables('OUTPUT')
    #parse the output into a list of lists, where each inner list represents a row of the iptables output
    table_data = parse_iptables_output(output_status)
    return render_template('home/status.html', table_data=table_data, chain='OUTPUT')

@blueprint.route('/forward_status')
@login_required
def forward_status():
    forward_status = query_iptables('FORWARD')
    #parse the output into a list of lists, where each inner list represents a row of the iptables output
    table_data = parse_iptables_output(forward_status)
    return render_template('home/status.html', table_data=table_data,   chain='FORWARD')


def query_iptables(chain):
    command = "echo {} | sudo -S iptables -L {} --line-numbers".format(sudo_password, chain)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
    output = process.communicate()
    return output[0].decode('utf-8')
def parse_iptables_output(output):
    #parse the output into a list of lists, where each inner list represents a row of the iptables output
    #the inner lists must have the following format: [num, target, prot, opt, source, destination, s_port, d_port, detail], if the corresponding field is not present in the output, the value should be an empty string
    #example output: 7    DROP       tcp  --  192.168.7.2          123.145.1.2          tcp spt:12 dpt:1233
    #the correct format should be: ['7', 'DROP', 'tcp', '--', '192.168.7.2', '123.145.1.2', '12', '1233', 'tcp']
    table_data = []
    lines = output.split('\n')
    #skip the last empty line
    lines = lines[:-1]
    for line in lines:
        if line.startswith('Chain'):
            continue
        if line.startswith('target'):
            continue
        if line.startswith('num'):
            continue
        parts = line.split()
        num = parts[0]
        target = parts[1]
        prot = parts[2]
        opt = parts[3]
        source = parts[4]
        destination = parts[5]
        
        s_port_match = re.search(r'spt:(\S+)', line)
        s_port = s_port_match.group(1) if s_port_match else 'any'
        
        d_port_match = re.search(r'dpt:(\S+)', line)
        d_port = d_port_match.group(1) if d_port_match else 'any'
        
        # Remove the known fields from the line to get the detail
        detail = line
        for field in [num, target, prot, opt, source, destination, f'spt:{s_port}', f'dpt:{d_port}']:
            detail = detail.replace(field, '', 1).strip()
        
        table_data.append([num, target, prot, opt, source, destination, s_port, d_port, detail])
    return table_data

def validate_iptables_command(command):
    # Define a strict regular expression to match valid iptables commands
    iptables_pattern = re.compile(
        r"^sudo\s+iptables\s+"
        r"(-[A-Z]\s+)?"
        r"(-[a-zA-Z0-9-]+(\s+[a-zA-Z0-9.:/-]+)*)\s*"
        r"(-j\s+[A-Z]+)?$"
    )

    # Check if the command matches the pattern
    if not iptables_pattern.match(command):
        return False

    # Ensure the command does not contain any potentially harmful characters or sequences
    forbidden_patterns = [
        r";",  # Command chaining
        r"&",  # Background execution
        r"\|",  # Pipe
        r"`",  # Command substitution
        r"\$",  # Variable substitution
        r">",  # Output redirection
        r"<",  # Input redirection
    ]

    for pattern in forbidden_patterns:
        if re.search(pattern, command):
            return False

    # Validate command structure further
    allowed_keywords = [
        # Chain names
        "INPUT", "OUTPUT", "FORWARD",
        
        # Actions
        "ACCEPT", "DROP", "REJECT", "LOG", "RETURN",
        
        # Common flags
        "-A", "-D", "-I", "-R", "-L", "-F", "-P", "-N", "-X",
        "-s", "-d", "-p", "-m", "-j", "-o", "-i", "--dport", "--sport",
        "--source-port", "--destination-port", "--icmp-type", 
        
        # Protocols
        "tcp", "udp", "icmp", "all",
        
        # Match extensions
        "--ctstate", "--state", "--match", "--conntrack", 
        "--limit", "--limit-burst", "--uid-owner", "--gid-owner",
        "--comment", 
        
        # Connection states
        "NEW", "ESTABLISHED", "RELATED", "INVALID"
    ]
    
    command_parts = command.split()
    for part in command_parts:
        # Skip options with values (e.g., IPs, ports, or comments) as they're dynamic
        if part.startswith("-") or part.startswith("--"):
            if part not in allowed_keywords:
                return False

    return True

def sanitize_input(input_value):
    # Implement input sanitization logic here
    return html.escape(input_value)

def is_valid_chain(chain):
    return chain in ['INPUT', 'OUTPUT', 'FORWARD']

def is_valid_rule_number(rule_number):
    try:
        rule_number = int(rule_number)
        return rule_number > 0
    except ValueError:
        return False

def parse_log_file():
    log_file = '/var/log/iptables.log'
    log_entries = []

    with open(log_file, 'r') as file:
        for line in file:
            log_entries.append(parse_log_line(line))

    return log_entries
@blueprint.route('/view_log')
@login_required
def view_log():
    log_entries = parse_log_file()
    return render_template('home/view_log.html', log_entries=log_entries)

def parse_log_line(line):
    # Define the regex pattern
    pattern = re.compile(
        r'(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+kernel:\s+(?P<chain>[A-Z]+)\s+LOG:\s+'
        r'IN=(?P<in_interface>\S*)\s+OUT=(?P<out_interface>\S*)\s+'
        r'(?:MAC=(?P<mac>[A-Fa-f0-9: ]+)\s+)?'
        r'SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+)\s+LEN=(?P<length>\d+)\s+'
        r'TOS=(?P<tos>\S+)\s+PREC=(?P<prec>\S+)\s+'
        r'TTL=(?P<ttl>\d+)\s+ID=(?P<id>\d+)\s+'
        r'(?:DF\s+)?PROTO=(?P<protocol>\S+)\s+'
        r'(?:SPT=(?P<src_port>\d+)\s+DPT=(?P<dst_port>\d+)\s+)?'
        r'(?:TYPE=(?P<type>\d+)\s+CODE=(?P<code>\d+)\s+ID=(?P<icmp_id>\d+)\s+SEQ=(?P<icmp_seq>\d+)\s+)?'
        r'(?:WINDOW=(?P<window>\d+)\s+RES=(?P<res>\S+)\s+)?'
        r'(?P<detail>.+)?'
    )

    # Match the line using the pattern
    match = pattern.match(line)

    # If the pattern matches, return a dictionary of parsed fields
    if match:
        return match.groupdict()
    return {}
import json
@blueprint.route('/data_visualization')
@login_required
def data_visualization():
    log_entries = parse_log_file()
    if not log_entries:
        return "No log entries to visualize."

    # Fields to visualize
    fields = ["src_ip", "dst_ip", "protocol", "in_interface", "out_interface", "detail"]
    
    # Aggregated data for each field
    aggregated_data = {}
    for field in fields:
        values = [entry[field] for entry in log_entries if field in entry and entry[field]]
        if values:
            counter = Counter(values)
            aggregated_data[field] = [[key, value] for key, value in counter.items()]

    # Convert the aggregated data to JSON format for rendering in the template
    aggregated_data_json = json.dumps(aggregated_data, indent=4)
    logging.debug(f"Aggregated data: {aggregated_data}")


    return render_template('home/data_visualization.html', aggregated_data=aggregated_data_json)
# Hiển thị và xử lý người dùng
from sqlalchemy.orm import joinedload
@blueprint.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_users():
    if request.method == 'POST':
        # Check the number of forms submitted
        num_forms = len([key for key in request.form.keys() if key.startswith('username_')])
        for i in range(num_forms):
            username = request.form.get(f'username_{i}')
            password = request.form.get(f'password_{i}')
            role = request.form.get(f'role_{i}')
            managers = request.form.getlist(f'managers_{i}') # Lấy danh sách managers
            viewers = request.form.getlist(f'viewers_{i}')   # Lấy danh sách viewers

            # Check if the username already exists
            if Users.query.filter_by(username=username).first():
                flash(f"The account {username} already exists.", 'danger')
                continue

            hashed_password = hash_pass(password)
            new_user = Users(username=username, password_hash=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()

            # Add permissions for the selected nodes
            for node_id in managers:
                user_node = UserNodes(user_id=new_user.id, node_id=node_id, role='manager')
                db.session.add(user_node)
            for node_id in viewers:
                user_node = UserNodes(user_id=new_user.id, node_id=node_id, role='viewer')
                db.session.add(user_node)
            db.session.commit()

            flash(f"Account {username} has been created.", 'success')

        return redirect(url_for('home_blueprint.manage_users'))

    # Khi method là GET, tải users với eager loading cho user_nodes và node
    users = Users.query.options(
        joinedload(Users.user_nodes).joinedload(UserNodes.node)
    ).all()
    nodes = Nodes.query.all()
    return render_template('home/manage_users.html', users=users, nodes=nodes)

# Delete user
@blueprint.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    user = Users.query.get_or_404(user_id)

    if user.username == current_user.username:
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('home_blueprint.manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f"Account {user.username} has been deleted.", 'success')
    return redirect(url_for('home_blueprint.manage_users'))

# 1. Route to return user data as JSON
@blueprint.route('/get_user_data/<int:user_id>')
@login_required
@role_required('admin')
def get_user_data(user_id):
    u = Users.query.get_or_404(user_id)
    # Lấy tất cả các bản ghi UserNodes liên quan đến user_id
    user_nodes = UserNodes.query.filter_by(user_id=user_id).all()

    mans = [row.node_id for row in user_nodes if row.role == 'manager']
    vies = [row.node_id for row in user_nodes if row.role == 'viewer']

    return jsonify({
        'id': u.id,
        'username': u.username,
        'role': u.role,
        'managers': mans,
        'viewers': vies
    })
@blueprint.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_user(user_id):
    u = Users.query.get_or_404(user_id)
    username = request.form['username'].strip()
    password = request.form.get('password', '').strip()
    role = request.form['role']
    mans = list(map(int, request.form.getlist('managers')))
    vies = list(map(int, request.form.getlist('viewers')))

    if username != u.username and Users.query.filter_by(username=username).first():
        flash("Username exists.", 'danger')
        return redirect(url_for('home_blueprint.manage_users'))

    # Kiểm tra xem có node nào được chọn đồng thời ở cả managers và viewers không
    common_nodes = set(mans) & set(vies)
    if common_nodes:
        flash(f"Node(s) {', '.join(map(str, common_nodes))} cannot be both managed and viewed.", 'danger')
        return redirect(url_for('home_blueprint.manage_users'))

    u.username = username
    u.role = role
    if password:
        u.password_hash = hash_pass(password)
    db.session.commit()

    # Xoá tất cả quan hệ cũ
    UserNodes.query.filter_by(user_id=u.id).delete()
    # Thêm lại viewer trước
    for nid in vies:
        db.session.add(UserNodes(user_id=u.id, node_id=nid, role='viewer'))
    # Thêm manager
    for nid in mans:
        db.session.add(UserNodes(user_id=u.id, node_id=nid, role='manager'))
    db.session.commit()

    flash("Account updated.", 'success')
    return redirect(url_for('home_blueprint.manage_users'))
# Manage Nodes (GET displays, POST adds new)
@blueprint.route('/manage_nodes', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_nodes():
    if request.method == 'POST':
        # Count the number of add forms
        num = len([k for k in request.form.keys() if k.startswith('hostname_')])
        for i in range(num):
            hostname    = request.form.get(f'hostname_{i}').strip()
            ip_address = request.form.get(f'ip_address_{i}').strip()
            ssh_user    = request.form.get(f'ssh_user_{i}').strip()
            ssh_key     = request.form.get(f'ssh_key_{i}', '').strip()
            viewers = list(map(int, request.form.getlist('viewers_{}'.format(i))))
            managers = list(map(int, request.form.getlist('managers_{}'.format(i))))

            # Check for duplicate hostname / ip
            if Nodes.query.filter_by(hostname=hostname).first():
                flash(f"Hostname '{hostname}' already exists.", 'danger')
                continue
            if Nodes.query.filter_by(ip_address=ip_address).first():
                flash(f"IP '{ip_address}' already exists.", 'danger')
                continue

            node = Nodes(hostname=hostname,
                         ip_address=ip_address,
                         ssh_user=ssh_user,
                         ssh_key=ssh_key)
            db.session.add(node)
            db.session.commit()

            # Assign managers
            for uid in managers:
                db.session.add(UserNodes(user_id=uid, node_id=node.id, role='manager'))
            for uid in viewers:
                db.session.add(UserNodes(user_id=uid, node_id=node.id, role='viewer'))
            db.session.commit()
            flash(f"Created Node '{hostname}'.", 'success')

        return redirect(url_for('home_blueprint.manage_nodes'))

    nodes = Nodes.query.all()
    users = Users.query.all()
    return render_template('home/manage_nodes.html', nodes=nodes, users=users)


# Delete Node
@blueprint.route('/delete_node/<int:node_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_node(node_id):
    node = Nodes.query.get_or_404(node_id)
    # Delete related user_nodes
    UserNodes.query.filter_by(node_id=node_id).delete()
    db.session.delete(node)
    db.session.commit()
    flash(f"Deleted Node '{node.hostname}'.", 'success')
    return redirect(url_for('home_blueprint.manage_nodes'))


# Get Node data (JSON) for edit modal
@blueprint.route('/get_node_data/<int:node_id>')
@login_required
@role_required('admin')
def get_node_data(node_id):
    node = Nodes.query.get_or_404(node_id)
    managers = [un.user_id for un in UserNodes.query.filter_by(node_id=node_id)]
    return jsonify({
        'hostname': node.hostname,
        'ip_address': node.ip_address,
        'ssh_user': node.ssh_user,
        'ssh_key': node.ssh_key,
        'managers': managers
    })


# Update Node
@blueprint.route('/update_node/<int:node_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_node(node_id):
    node = Nodes.query.get_or_404(node_id)
    hostname    = request.form.get('hostname').strip()
    ip_address = request.form.get('ip_address').strip()
    ssh_user    = request.form.get('ssh_user').strip()
    ssh_key     = request.form.get('ssh_key', '').strip()
    viewers = list(map(int, request.form.getlist('viewers')))
    managers= list(map(int, request.form.getlist('managers')))
    UserNodes.query.filter_by(node_id=node.id).delete()
    for uid in viewers:
        db.session.add(UserNodes(user_id=uid, node_id=node.id, role='viewer'))
    for uid in managers:
        db.session.add(UserNodes(user_id=uid, node_id=node.id, role='manager'))
    db.session.commit()
    # Check for duplicates
    if hostname != node.hostname and Nodes.query.filter_by(hostname=hostname).first():
        flash(f"Hostname '{hostname}' already exists.", 'danger')
        return redirect(url_for('home_blueprint.manage_nodes'))
    if ip_address != node.ip_address and Nodes.query.filter_by(ip_address=ip_address).first():
        flash(f"IP '{ip_address}' already exists.", 'danger')
        return redirect(url_for('home_blueprint.manage_nodes'))

    # Update
    node.hostname    = hostname
    node.ip_address = ip_address
    node.ssh_user    = ssh_user
    node.ssh_key     = ssh_key
    db.session.commit()

    # Synchronize managers
    existing = {un.user_id for un in UserNodes.query.filter_by(node_id=node.id)}
    to_remove = existing - set(managers)
    to_add    = set(managers) - existing

    if to_remove:
        UserNodes.query.filter(
            UserNodes.node_id==node.id,
            UserNodes.user_id.in_(to_remove)
        ).delete(synchronize_session=False)

    for uid in to_add:
        db.session.add(UserNodes(user_id=uid, node_id=node.id, role='manager'))

    db.session.commit()
    flash(f"Updated Node '{node.hostname}'.", 'success')
    return redirect(url_for('home_blueprint.manage_nodes'))
def run_ssh_on_node(node, cmd):
    """
    Runs command cmd via SSH on the node. node.ssh_key can be:
    - Path to the private key file
    - Or the key content itself (starts with '-----BEGIN')
    """
    # Create a temporary file if needed
    if node.ssh_key.strip().startswith('-----BEGIN'):
        tf = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.pem')
        tf.write(node.ssh_key)
        tf.close()
        os.chmod(tf.name, stat.S_IRUSR)   # 0400
        key_path = tf.name
        remove_after = True
    else:
        key_path = node.ssh_key
        remove_after = False

    ssh_cmd = (
        f"ssh -i {key_path} "
        "-o StrictHostKeyChecking=no "
        f"{node.ssh_user}@{node.ip_address} "
        f"\"{cmd}\""
    )
    res = subprocess.run(
        ssh_cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True
    )
    if remove_after:
        try: os.remove(key_path)
        except: pass
    return res
# --- Manage Rules ---
#function to add rule to the INPUT chain in iptables
@blueprint.route('/add_rule', methods=['GET', 'POST'])
@login_required
def add_rule():
    # only nodes where the user has role='manager'
    mgr_entries = UserNodes.query.filter_by(user_id=current_user.id, role='manager').all()
    node_ids    = [un.node_id for un in mgr_entries]
    nodes       = Nodes.query.filter(Nodes.id.in_(node_ids)).all()

    if request.method == 'POST':
        selected = list(map(int, request.form.getlist('node_ids')))
        # permission check
        if not selected or any(nid not in node_ids for nid in selected):
            flash('You do not have permission to add rules on one or more selected nodes.', 'danger')
            return redirect(url_for('home_blueprint.add_rule'))

        manual = request.form.get('manual_rule','').strip()
        cmds = []
        if manual:
            if not validate_iptables_command(manual):
                flash('Invalid iptables command.', 'danger')
                return redirect(url_for('home_blueprint.add_rule'))
            cmds = [manual]
        else:
            chains  = request.form.getlist('chain[]')
            targets = request.form.getlist('target[]')
            prots   = request.form.getlist('prot[]')
            srcs    = request.form.getlist('source[]')
            dsts    = request.form.getlist('destination[]')
            sports  = request.form.getlist('sport[]')
            dports  = request.form.getlist('dport[]')
            for c,t,p,src,dst,sp,dp in zip(chains, targets, prots, srcs, dsts, sports, dports):
                cmd = f"iptables -A {c} -p {p} -s {src} -d {dst} -j {t}"
                if sp: cmd += f" --sport {sp}"
                if dp: cmd += f" --dport {dp}"
                cmds.append(cmd)

        # execute via SSH
        for nid in selected:
            node = next(n for n in nodes if n.id==nid)
            for cmd in cmds:
                res = run_ssh_on_node(node, cmd)
                if res.returncode != 0:
                    flash(f"Error on node {node.hostname}: {res.stderr}", 'danger')
                    return redirect(url_for('home_blueprint.add_rule'))

        flash('Rules added successfully!', 'success')
        return redirect(url_for('home_blueprint.view_status'))

    return render_template('home/add_rules.html', nodes=nodes)

@blueprint.route('/view_status')
@login_required
@role_required('admin', 'user')
def view_status():
    # both manager & viewer can view
    entries = UserNodes.query.filter_by(user_id=current_user.id).all()
    node_ids = [un.node_id for un in entries]
    nodes    = Nodes.query.filter(Nodes.id.in_(node_ids)).all()

    status = {}
    for node in nodes:
        status[node.id] = {}
        for chain in ['INPUT','OUTPUT','FORWARD']:
            cmd = f"iptables -L {chain} --line-numbers"
            res = run_ssh_on_node(node, cmd)
            if res.returncode == 0:
                status[node.id][chain] = parse_iptables_output(res.stdout)
            else:
                status[node.id][chain] = [[ 'ERR', res.stderr ]]
    return render_template('home/view_status.html', nodes=nodes, status=status)

@blueprint.route('/delete_rule')
@login_required
@role_required('admin', 'user')
def delete_rule():
    """
    URL params: node_id, chain, rule_number
    """
    try:
        nid     = int(request.args.get('node_id'))
        chain   = request.args.get('chain','').upper()
        rn      = int(request.args.get('rule_number'))
    except:
        flash('Invalid parameters.', 'danger')
        return redirect(url_for('home_blueprint.view_status'))

    # check if only manager can delete
    if not UserNodes.query.filter_by(
            user_id=current_user.id,
            node_id=nid,
            role='manager'
        ).first():
        flash('You do not have permission to delete rules on this node.', 'danger')
        return redirect(url_for('home_blueprint.view_status'))

    node = Nodes.query.get_or_404(nid)
    cmd = f"iptables -D {chain} {rn}"
    res = run_ssh_on_node(node, cmd)
    if res.returncode != 0:
        flash(f"Error deleting on {node.hostname}: {res.stderr}", 'danger')
    else:
        flash('Rule deleted successfully.', 'success')

    return redirect(url_for('home_blueprint.view_status'))