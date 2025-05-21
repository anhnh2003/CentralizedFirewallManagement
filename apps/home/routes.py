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
# Helper function to run ssh-copy-id
def run_ssh_copy_id(user, ip, password):
    """
    Thực thi lệnh ssh-copy-id với mật khẩu.
    Trả về (True, "Thông báo thành công") hoặc (False, "Thông báo lỗi").
    """
    # Tạo một script expect tạm thời để tự động nhập mật khẩu
    expect_script_content = f"""
#!/usr/bin/expect -f
set timeout 20
spawn ssh-copy-id {user}@{ip}
expect {{
    "(yes/no)?" {{ send "yes\\r"; exp_continue }}
    "password:" {{ send "{password}\\r" }}
    "Password:" {{ send "{password}\\r" }}
    "All keys were already added" {{ puts "All keys were already added"; exit 0 }}
    timeout {{ puts "Timeout occurred"; exit 1 }}
    eof {{ puts "EOF reached"; exit 1 }}
}}
expect eof
"""
    tf = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.exp')
    tf.write(expect_script_content)
    tf.close()
    os.chmod(tf.name, stat.S_IXUSR | stat.S_IRUSR) # Cấp quyền thực thi và đọc

    try:
        result = subprocess.run(
            [tf.name],
            capture_output=True,
            text=True,
            check=False # Không raise exception cho mã thoát khác 0
        )
        # Kiểm tra các thông báo thành công từ ssh-copy-id
        if "Number of key(s) added: 1" in result.stdout or "All keys were already added" in result.stdout:
            return True, "SSH key đã được sao chép thành công hoặc đã tồn tại."
        else:
            return False, f"ssh-copy-id thất bại: {result.stderr.strip() or result.stdout.strip()}"
    except Exception as e:
        return False, f"Lỗi khi thực thi script ssh-copy-id: {e}"
    finally:
        if os.path.exists(tf.name):
            os.remove(tf.name) # Dọn dẹp script tạm thời


# Helper function to generate SSH keys
def generate_ssh_keys():
    """
    Tạo cặp khóa SSH private và public (~/.ssh/id_rsa và ~/.ssh/id_rsa.pub).
    Trả về (True, "Thông báo thành công") hoặc (False, "Thông báo lỗi").
    """
    ssh_dir = os.path.expanduser("~/.ssh")
    private_key_path = os.path.join(ssh_dir, "id_rsa")
    public_key_path = os.path.join(ssh_dir, "id_rsa.pub")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return True, "SSH keys đã tồn tại."

    os.makedirs(ssh_dir, exist_ok=True) # Đảm bảo thư mục ~/.ssh tồn tại

    try:
        # Tạo SSH keys không có passphrase cho mục đích tự động hóa
        # -t rsa: loại khóa
        # -b 4096: độ dài khóa
        # -f: tên file đầu ra
        # -N "": không có passphrase
        result = subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", private_key_path, "-N", ""],
            capture_output=True,
            text=True,
            check=True # Raise exception cho mã thoát khác 0
        )
        os.chmod(private_key_path, stat.S_IRUSR) # Đặt quyền 0400 cho private key
        return True, f"SSH keys đã được tạo thành công: {private_key_path}, {public_key_path}"
    except subprocess.CalledProcessError as e:
        return False, f"Không thể tạo SSH keys: {e.stderr.strip()}"
    except Exception as e:
        return False, f"Một lỗi không mong muốn đã xảy ra trong quá trình tạo khóa: {e}"


@blueprint.route('/manage_nodes', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'user') # Đảm bảo bạn đã định nghĩa role_required decorator
def manage_nodes():
    if request.method == 'POST':
        # KIỂM TRA QUYỀN HẠN: CHỈ ADMIN MỚI ĐƯỢC THÊM NODE
        if current_user.role != 'admin':
            flash("Bạn không có quyền thêm node.", 'danger')
            return redirect(url_for('home_blueprint.manage_nodes'))
        # --- Kiểm tra và Tạo SSH Keys nếu chưa tồn tại ---
        key_gen_success, key_gen_message = generate_ssh_keys()
        if not key_gen_success:
            flash(f"Lỗi thiết lập SSH key cục bộ: {key_gen_message}. Không thể thêm/cập nhật node.", 'danger')
            return redirect(url_for('home_blueprint.manage_nodes'))
        else:
            flash(key_gen_message, 'info') # Thông báo về việc tạo/tồn tại khóa

        local_ssh_public_key_path = os.path.expanduser("~/.ssh/id_rsa.pub")

        # Đếm số lượng form thêm
        num_forms = len([key for key in request.form.keys() if key.startswith('hostname_')])
        for i in range(num_forms):
            hostname = request.form.get(f'hostname_{i}').strip()
            ip_address = request.form.get(f'ip_address_{i}').strip()
            ssh_user = request.form.get(f'ssh_user_{i}').strip()
            password = request.form.get(f'password_{i}', '').strip() # Lấy mật khẩu từ trường 'password'

            # Lấy người quản lý và người xem đã chọn cho node này
            # Lưu ý: Tên trong HTML là managers_{i} và viewers_{i}
            managers_for_node = list(map(int, request.form.getlist(f'managers_{i}')))
            viewers_for_node = list(map(int, request.form.getlist(f'viewers_{i}')))

            # Backend Check: Node không thể vừa là người quản lý vừa là người xem bởi cùng một người dùng
            common_users = set(managers_for_node) & set(viewers_for_node)
            if common_users:
                # Lấy tên người dùng để thông báo lỗi rõ ràng hơn
                common_usernames = [u.username for u in Users.query.filter(Users.id.in_(list(common_users))).all()]
                flash(f"Node '{hostname}': Người dùng '{', '.join(common_usernames)}' không thể vừa là người quản lý vừa là người xem cho node này.", 'danger')
                continue # Bỏ qua node này và tiếp tục với form tiếp theo

            # Kiểm tra trùng lặp hostname / ip
            if Nodes.query.filter_by(hostname=hostname).first():
                flash(f"Hostname '{hostname}' đã tồn tại.", 'danger')
                continue
            if Nodes.query.filter_by(ip_address=ip_address).first():
                flash(f"IP '{ip_address}' đã tồn tại.", 'danger')
                continue

            # --- Logic Sao chép SSH Key ---
            public_key_content = None # Sẽ lưu nội dung public key vào đây

            # Chỉ thử ssh-copy-id nếu mật khẩu được cung cấp VÀ public key tồn tại cục bộ
            if password and os.path.exists(local_ssh_public_key_path):
                flash(f"Đang cố gắng sao chép SSH key đến {ssh_user}@{ip_address}...", 'info')
                success, message = run_ssh_copy_id(ssh_user, ip_address, password)
                if success:
                    flash(f"SSH key đã được sao chép đến {ssh_user}@{ip_address}: {message}", 'success')
                    with open(local_ssh_public_key_path, 'r') as f:
                        public_key_content = f.read().strip() # Đọc nội dung public key
                else:
                    flash(f"Không thể sao chép SSH key đến {ssh_user}@{ip_address}: {message}", 'danger')
                    # Nếu ssh-copy-id thất bại, không thêm node này
                    continue
            elif not password:
                flash(f"Không có mật khẩu được cung cấp để thiết lập SSH key cho {hostname}. Giả sử key đã được thiết lập hoặc sẽ được thực hiện thủ công.", 'warning')
            # Không cần kiểm tra os.path.exists(local_ssh_public_key_path) ở đây nữa vì đã kiểm tra ở đầu hàm POST

            # Lưu node, trường ssh_key sẽ là nội dung public key hoặc None/rỗng
            node = Nodes(hostname=hostname,
                         ip_address=ip_address,
                         ssh_user=ssh_user,
                         ssh_key=public_key_content) # Lưu nội dung public key
            db.session.add(node)
            db.session.commit() # Commit ở đây để lấy node.id

            # Gán người quản lý và người xem cho node vừa tạo
            for uid in managers_for_node:
                db.session.add(UserNodes(user_id=uid, node_id=node.id, role='manager'))
            for uid in viewers_for_node:
                db.session.add(UserNodes(user_id=uid, node_id=node.id, role='viewer'))
            db.session.commit()

            flash(f"Đã tạo Node '{hostname}'.", 'success')

        return redirect(url_for('home_blueprint.manage_nodes'))

    # GET request: Tải nodes với eager loading cho user_nodes và user
    nodes = Nodes.query.options(
        joinedload(Nodes.user_nodes).joinedload(UserNodes.user)
    ).all()
    users = Users.query.all() # Cần tất cả người dùng cho các form
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
@role_required('admin','user')
def get_node_data(node_id):
    node = Nodes.query.options(
        joinedload(Nodes.user_nodes)
    ).get_or_404(node_id)

    managers = [un.user_id for un in node.user_nodes if un.role == 'manager']
    viewers = [un.user_id for un in node.user_nodes if un.role == 'viewer']

    return jsonify({
        'id': node.id,
        'hostname': node.hostname,
        'ip_address': node.ip_address,
        'ssh_user': node.ssh_user,
        'managers': managers,
        'viewers': viewers
    })
# Update Node
@blueprint.route('/update_node/<int:node_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_node(node_id):
    node = Nodes.query.get_or_404(node_id)
    hostname = request.form['hostname'].strip()
    ip_address = request.form['ip_address'].strip()
    ssh_user = request.form['ssh_user'].strip()
    password = request.form.get('password', '').strip() # Lấy mật khẩu để cập nhật key tiềm năng

    managers = list(map(int, request.form.getlist('managers')))
    viewers = list(map(int, request.form.getlist('viewers')))

    # Backend Check: Node không thể vừa là người quản lý vừa là người xem bởi cùng một người dùng
    common_users = set(managers) & set(viewers)
    if common_users:
        common_usernames = [u.username for u in Users.query.filter(Users.id.in_(list(common_users))).all()]
        flash(f"Node '{hostname}': Người dùng '{', '.join(common_usernames)}' không thể vừa là người quản lý vừa là người xem cho node này.", 'danger')
        return redirect(url_for('home_blueprint.manage_nodes'))

    # Kiểm tra trùng lặp hostname / ip (loại trừ node hiện tại)
    if Nodes.query.filter(Nodes.hostname == hostname, Nodes.id != node_id).first():
        flash(f"Hostname '{hostname}' đã tồn tại.", 'danger')
        return redirect(url_for('home_blueprint.manage_nodes'))
    if Nodes.query.filter(Nodes.ip_address == ip_address, Nodes.id != node_id).first():
        flash(f"IP '{ip_address}' đã tồn tại.", 'danger')
        return redirect(url_for('home_blueprint.manage_nodes'))

    # --- SSH Key Update Logic ---
    # Kiểm tra và Tạo SSH Keys nếu chưa tồn tại trước khi cố gắng sao chép
    key_gen_success, key_gen_message = generate_ssh_keys()
    if not key_gen_success:
        flash(f"Lỗi thiết lập SSH key cục bộ: {key_gen_message}. Không thể cập nhật node.", 'danger')
        return redirect(url_for('home_blueprint.manage_nodes'))
    else:
        flash(key_gen_message, 'info') # Thông báo về việc tạo/tồn tại khóa

    # Chỉ thử ssh-copy-id nếu mật khẩu được cung cấp VÀ public key tồn tại cục bộ
    local_ssh_public_key_path = os.path.expanduser("~/.ssh/id_rsa.pub")
    if password and os.path.exists(local_ssh_public_key_path):
        flash(f"Đang cố gắng sao chép SSH key đến {ssh_user}@{ip_address}...", 'info')
        success, message = run_ssh_copy_id(ssh_user, ip_address, password)
        if success:
            flash(f"SSH key đã được sao chép đến {ssh_user}@{ip_address}: {message}", 'success')
        else:
            flash(f"Không thể sao chép SSH key đến {ssh_user}@{ip_address}: {message}", 'danger')
            # Nếu ssh-copy-id thất bại, chúng ta không cập nhật node.ssh_key
            # và sẽ giữ nguyên giá trị cũ (hoặc None nếu trước đó là None)
    elif not password:
        flash(f"Không có mật khẩu được cung cấp để thiết lập SSH key cho {hostname}. Giả sử key đã được thiết lập hoặc sẽ được thực hiện thủ công.", 'warning')
    # Không cần kiểm tra os.path.exists(local_ssh_public_key_path) ở đây nữa vì đã kiểm tra ở đầu hàm POST và update


    node.hostname = hostname
    node.ip_address = ip_address
    node.ssh_user = ssh_user
    # node.ssh_key = public_key_content_to_store # Bỏ dòng này
    db.session.commit()

    # Cập nhật quan hệ UserNodes
    UserNodes.query.filter_by(node_id=node.id).delete() # Xóa tất cả quan hệ hiện có cho node này
    for uid in managers:
        db.session.add(UserNodes(user_id=uid, node_id=node.id, role='manager'))
    for uid in viewers:
        db.session.add(UserNodes(user_id=uid, node_id=node.id, role='viewer'))
    db.session.commit()

    flash(f"Node '{hostname}' đã được cập nhật.", 'success')
    return redirect(url_for('home_blueprint.manage_nodes'))
def run_ssh_on_node(node, cmd):
    """
    Chạy cmd qua SSH trên node, dùng private key tại ~/.ssh/id_rsa
    """
    key_path = os.path.expanduser("~/.ssh/id_rsa")
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
                cmd = f"sudo iptables -A {c} -p {p} -s {src} -d {dst} -j {t}"
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
            cmd = f"sudo iptables -L {chain} --line-numbers"
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
    cmd = f"sudo iptables -D {chain} {rn}"
    res = run_ssh_on_node(node, cmd)
    if res.returncode != 0:
        flash(f"Error deleting on {node.hostname}: {res.stderr}", 'danger')
    else:
        flash('Rule deleted successfully.', 'success')

    return redirect(url_for('home_blueprint.view_status'))