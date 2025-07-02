# -*- encoding: utf-8 -*-
from apps.home import blueprint
from apps import db
from flask import render_template, request, flash, redirect, url_for, redirect, jsonify
from flask_login import login_required, current_user
from jinja2 import TemplateNotFound
import subprocess, tempfile, os, stat
import re
import html
from collections import Counter, defaultdict
import logging
from apps.home.util import role_required
from apps.authentication.util import hash_pass
from apps.authentication.models import Users, Nodes, UserNodes
from datetime import datetime, timedelta
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
def parse_iptables_output(output):
    """
    Parses the output of 'sudo iptables -L <chain> --line-numbers'.
    Returns a list of tuples, where each tuple is (rule_number, [Target, Prot, Opt, Source, Destination, Spt, Dpt, Detail]).
    Fields not present will be empty strings.
    """
    table_data = []
    lines = output.split('\n')

    # Regex để parse một dòng luật IPTables với --line-numbers
    # Các cột: num, target, prot, opt, source, destination
    # và phần còn lại là 'remaining_detail' (có thể chứa spt/dpt hoặc các flag khác)
    # Rất quan trọng: sử dụng '\s+' để khớp với 1 hoặc nhiều khoảng trắng
    # và `.*?` (non-greedy) để khớp đến khi gặp cột tiếp theo hoặc kết thúc dòng.
    pattern = re.compile(
        r'^\s*(?P<num>\d+)\s+'          # 1. Rule number
        r'(?P<target>\S+)\s+'         # 2. Target (e.g., ACCEPT, DROP)
        r'(?P<prot>\S+)\s+'           # 3. Protocol (e.g., tcp, udp, all)
        r'(?P<opt>\S+)\s+'            # 4. Opt (e.g., --)
        r'(?P<source>\S+)\s+'         # 5. Source IP/Hostname
        r'(?P<destination>\S+)\s*'    # 6. Destination IP/Hostname
        r'(?P<remaining_detail>.*)$'  # 7. All remaining details
    )

    for line in lines:
        line = line.strip()
        # Bỏ qua các dòng tiêu đề và dòng trống
        # Khi không có -v, dòng tiêu đề pkts có thể không xuất hiện, hoặc xuất hiện ở format khác.
        # Dòng 'num' và 'Chain' là đủ để lọc tiêu đề.
        if not line or line.startswith('Chain') or line.startswith('num'):
            continue

        match = pattern.match(line)
        if match:
            data = match.groupdict()
            
            num = int(data['num'])
            target = data['target']
            prot = data['prot']
            opt = data['opt']
            source = data['source']
            destination = data['destination']
            
            remaining_detail = data['remaining_detail'].strip()
            
            s_port = ''
            d_port = ''
            
            # Extract Source Port (SPT)
            spt_match = re.search(r'spt:(\S+)', remaining_detail)
            if spt_match:
                s_port = spt_match.group(1)
                # Loại bỏ phần SPT đã tìm thấy khỏi remaining_detail
                remaining_detail = remaining_detail.replace(spt_match.group(0), '').strip()
            
            # Extract Destination Port (DPT)
            dpt_match = re.search(r'dpt:(\S+)', remaining_detail)
            if dpt_match:
                d_port = dpt_match.group(1)
                # Loại bỏ phần DPT đã tìm thấy khỏi remaining_detail
                remaining_detail = remaining_detail.replace(dpt_match.group(0), '').strip()

            # Clean up any multiple spaces that might result from replacements
            detail_final = re.sub(r'\s+', ' ', remaining_detail).strip()

            # Chuẩn bị dữ liệu cho template
            rule_data = [
                target,
                prot,
                opt,
                source,
                destination,
                s_port,
                d_port,
                detail_final
            ]
            
            table_data.append((num, rule_data))
        else:
            # Nếu một dòng không khớp với định dạng luật mong đợi, có thể là dòng policy hoặc lỗi
            # Ví dụ: "Chain INPUT (policy ACCEPT)"
            # Bạn có thể xử lý các dòng này nếu muốn, hoặc bỏ qua như hiện tại.
            pass

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
def parse_log_line(line):
    # Cập nhật regex để khớp với định dạng log thực tế của bạn
    # Ví dụ: "May 23 15:03:27 vsclab kernel: [17826.753610] [IPTABLES] OUTPUT: IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.53 LEN=71 TOS=0x00 PREC=0x00 TTL=64 ID=11809 DF PROTO=UDP SPT=37526 DPT=53 LEN=51"
    
    pattern = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp: May 23 15:03:27
        r'(?P<hostname>\S+)\s+'                             # Hostname: vsclab
        r'kernel:\s+'                                       # "kernel: "
        r'\[(?P<kernel_timestamp>\d+\.\d+)\]\s+'            # Internal kernel timestamp: [17826.753610]
        r'\[IPTABLES\]\s+'                                  # "[IPTABLES] "
        r'(?P<chain>[A-Z]+):\s+'                            # Chain (OUTPUT/INPUT): "OUTPUT: " hoặc "INPUT: "
        r'IN=(?P<in_interface>\S*)\s+'                      # IN= (có thể rỗng)
        r'OUT=(?P<out_interface>\S*)\s+'                    # OUT= (có thể rỗng)
        r'(?:MAC=(?P<mac>[A-Fa-f0-9: ]+)\s+)?'              # MAC (tùy chọn)
        r'SRC=(?P<src_ip>\S+)\s+'                           # SRC=
        r'DST=(?P<dst_ip>\S+)\s+'                           # DST=
        r'LEN=(?P<length>\d+)\s+'                           # LEN=
        r'TOS=(?P<tos>\S+)\s+'                              # TOS=
        r'PREC=(?P<prec>\S+)\s+'                            # PREC=
        r'TTL=(?P<ttl>\d+)\s+'                              # TTL=
        r'ID=(?P<id>\d+)\s+'                                # ID=
        r'(?:DF\s+)?'                                       # DF (tùy chọn)
        r'PROTO=(?P<protocol>\S+)\s+'                       # PROTO=
        r'(?:SPT=(?P<src_port>\d+)\s+DPT=(?P<dst_port>\d+)\s+)?' # SPT/DPT (tùy chọn)
        r'(?:TYPE=(?P<type>\d+)\s+CODE=(?P<code>\d+)\s+ID=(?P<icmp_id>\d+)\s+SEQ=(?P<icmp_seq>\d+)\s+)?' # ICMP (tùy chọn)
        r'(?:WINDOW=(?P<window>\d+)\s+RES=(?P<res>\S+)\s+)?' # TCP Window (tùy chọn)
        r'(?P<detail>.*)?'                                  # Các phần còn lại (nếu có)
    )

    # Đảm bảo đây là .search()
    match = pattern.search(line)

    if match:
        return match.groupdict()
    else:
        # In ra dòng log không thể parse để debug thêm
        #print(f"DEBUG_PARSE_FINAL_CHECK: Could not parse line: {line.strip()}")
        return {}
import json
# --- View Logs from all nodes the user can access ---
@blueprint.route('/view_log')
@login_required
def view_log():
    user_allowed_nodes_info = {}
    node_entries = UserNodes.query.filter_by(user_id=current_user.id).all()
    for entry in node_entries:
        node = Nodes.query.get(entry.node_id)
        if node:
            user_allowed_nodes_info[node.ip_address] = {
                'node_id': node.id,
                'node_ip': node.ip_address
            }
    
    base_log_dir = "/var/log/remote/"
    all_entries = []

    logging.info(f"Đang tìm kiếm log trong thư mục: {base_log_dir}")

    if not os.path.exists(base_log_dir):
        flash(f"Thư mục log từ xa '{base_log_dir}' không tồn tại.", 'warning')
        logging.warning(f"Thư mục '{base_log_dir}' không tồn tại.")
        return render_template('home/view_log.html', log_entries=[])

    # Lấy danh sách các thư mục con trong base_log_dir
    client_ip_dirs = []
    try:
        client_ip_dirs = os.listdir(base_log_dir)
    except PermissionError as e:
        flash(f"Lỗi quyền khi liệt kê thư mục '{base_log_dir}': {e}", 'error')
        logging.error(f"Lỗi quyền khi liệt kê thư mục '{base_log_dir}': {e}")
        return render_template('home/view_log.html', log_entries=[])
    except Exception as e:
        flash(f"Lỗi không xác định khi liệt kê thư mục '{base_log_dir}': {e}", 'error')
        logging.error(f"Lỗi không xác định khi liệt kê thư mục '{base_log_dir}': {e}")
        return render_template('home/view_log.html', log_entries=[])

    logging.info(f"Tìm thấy các thư mục con: {client_ip_dirs}")

    for client_ip_dir in client_ip_dirs:
        # Bỏ qua các IP không hợp lệ hoặc localhost
        if client_ip_dir == '127.0.0.1' or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', client_ip_dir):
            logging.info(f"Bỏ qua thư mục không hợp lệ: {client_ip_dir}")
            continue

        # Chỉ xử lý các IP mà người dùng hiện tại có quyền truy cập
        if client_ip_dir not in user_allowed_nodes_info:
            logging.info(f"Bỏ qua thư mục '{client_ip_dir}' vì người dùng không có quyền.")
            continue

        current_node_info = user_allowed_nodes_info[client_ip_dir]
        node_id_for_log = current_node_info['node_id']
        node_ip_for_log = current_node_info['node_ip']

        iptables_log_path = os.path.join(base_log_dir, client_ip_dir, "iptables.log")
        logging.info(f"Đang kiểm tra file log: {iptables_log_path}")
        
        if os.path.exists(iptables_log_path):
            try:
                # Kiểm tra quyền của file trước khi mở (để debug)
                file_stat = os.stat(iptables_log_path)
                logging.info(f"Quyền của file {iptables_log_path}: {oct(file_stat.st_mode & 0o777)}")
                logging.info(f"Owner Uid: {file_stat.st_uid}, Gid: {file_stat.st_gid}")
                
                with open(iptables_log_path, 'r') as f:
                    lines_read = 0
                    for line in f:
                        lines_read += 1
                        # Loại bỏ ký tự xuống dòng ở cuối
                        stripped_line = line.strip()
                        if not stripped_line: # Bỏ qua dòng trống
                            continue

                        # Debug: In ra vài dòng đầu tiên để kiểm tra định dạng
                        if lines_read < 10: # Chỉ in 10 dòng đầu
                            logging.debug(f"Đọc dòng log: {stripped_line}")

                        entry = parse_log_line(stripped_line) # Truyền dòng đã strip
                        
                        if entry:
                            entry['node_id'] = node_id_for_log
                            entry['node_ip'] = node_ip_for_log
                            all_entries.append(entry)
                        else:
                            logging.warning(f"Không thể parse dòng log từ {iptables_log_path}: '{stripped_line}'")
                    logging.info(f"Đã đọc {lines_read} dòng từ {iptables_log_path}. Tổng số entry hợp lệ: {len(all_entries)}")

            except PermissionError as e:
                flash(f"Lỗi quyền khi đọc file log '{iptables_log_path}': {e}", 'error')
                logging.error(f"Lỗi quyền khi đọc file log '{iptables_log_path}': {e}")
            except Exception as e:
                flash(f"Lỗi không xác định khi đọc file log '{iptables_log_path}': {e}", 'error')
                logging.error(f"Lỗi không xác định khi đọc file log '{iptables_log_path}': {e}")
        else:
            flash(f"File '{iptables_log_path}' không tồn tại.", 'info')
            logging.info(f"File '{iptables_log_path}' không tồn tại.")

    logging.info(f"Tổng số entries sẽ được hiển thị: {len(all_entries)}")
    return render_template('home/view_log.html', log_entries=all_entries)

# --- Data Visualization from all accessible nodes ---
@blueprint.route('/data_visualization')
@login_required
def data_visualization():
    user_allowed_ips = set()
    node_entries = UserNodes.query.filter_by(user_id=current_user.id).all()
    for entry in node_entries:
        node = Nodes.query.get(entry.node_id)
        if node:
            user_allowed_ips.add(node.ip_address)

    base_log_dir = "/var/log/remote/"
    all_entries = []

    if not os.path.exists(base_log_dir):
        flash(f"Thư mục log từ xa '{base_log_dir}' không tồn tại.", 'warning')
        # Trả về đối tượng dictionary rỗng thay vì chuỗi JSON rỗng
        return render_template('home/data_visualization.html', aggregated_data={}) 

    for client_ip_dir in os.listdir(base_log_dir):
        if client_ip_dir == '127.0.0.1' or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', client_ip_dir):
            continue

        if client_ip_dir not in user_allowed_ips:
            continue

        iptables_log_path = os.path.join(base_log_dir, client_ip_dir, "iptables.log")

        if os.path.exists(iptables_log_path):
            try:
                with open(iptables_log_path, 'r') as f:
                    for line in f:
                        entry = parse_log_line(line)
                        if entry:
                            entry['client_ip'] = client_ip_dir
                            all_entries.append(entry)
            except Exception as e:
                print(f"Error reading log file {iptables_log_path}: {e}")

    if not all_entries:
        flash("Không có bản ghi log nào để hiển thị dữ liệu.", 'warning')
        # Trả về đối tượng dictionary rỗng
        return render_template('home/data_visualization.html', aggregated_data={})

    fields = ["src_ip", "dst_ip", "protocol", "in_interface", "out_interface", "client_ip"]
    aggregated_data = {}
    for field in fields:
        values = [e[field] for e in all_entries if e.get(field)]
        if values:
            cnt = Counter(values)
            aggregated_data[field] = [[k, v] for k, v in cnt.items()]

    # TRUYỀN TRỰC TIẾP ĐỐI TƯỢNG DICTIONARY VÀO TEMPLATE
    return render_template(
        'home/data_visualization.html',
        aggregated_data=aggregated_data # Bỏ json.dumps() 
    )
def parse_perf_log_line(line, log_type): # Enhanced log parsing
    # Lấy năm hiện tại và xử lý nếu ngày log có thể từ năm trước
    current_year = datetime.now().year
    try:
        match log_type:
            case "disk":
                match = re.match(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?ROOT_USAGE:(\d+)%", line)
                if match:
                    # Tạo datetime object ngay tại đây để dễ dàng so sánh và sắp xếp
                    # Cần cẩn thận với năm nếu log vượt qua ranh giới năm
                    try:
                        dt_obj = datetime.strptime(f"{match.group(1)} {current_year}", "%b %d %H:%M:%S %Y")
                    except ValueError: # Xử lý trường hợp log là cuối năm trước nhưng năm hiện tại là năm sau
                        dt_obj = datetime.strptime(f"{match.group(1)} {current_year - 1}", "%b %d %H:%M:%S %Y")
                    return {"timestamp": dt_obj, "root_usage": int(match.group(2))}
            case "cpu":
                 match = re.match(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?CPU_PERF.*?(\d+)%", line)
                 if match:
                    try:
                        dt_obj = datetime.strptime(f"{match.group(1)} {current_year}", "%b %d %H:%M:%S %Y")
                    except ValueError:
                        dt_obj = datetime.strptime(f"{match.group(1)} {current_year - 1}", "%b %d %H:%M:%S %Y")
                    return {"timestamp": dt_obj, "cpu_usage": int(match.group(2))}
            case "ram":
                match = re.match(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?RAM_PERF.*?Total:(\d+)MB, Used:(\d+)MB, Free:(\d+)MB", line)
                if match:
                    try:
                        dt_obj = datetime.strptime(f"{match.group(1)} {current_year}", "%b %d %H:%M:%S %Y")
                    except ValueError:
                        dt_obj = datetime.strptime(f"{match.group(1)} {current_year - 1}", "%b %d %H:%M:%S %Y")
                    return {"timestamp": dt_obj, "total_ram": int(match.group(2)), "used_ram": int(match.group(3)), "free_ram": int(match.group(4))}
            case "network":
                match = re.match(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?NETWORK_PERF.*?TCP_LISTEN:(\d+), TCP_ESTABLISHED:(\d+)", line)
                if match:
                    try:
                        dt_obj = datetime.strptime(f"{match.group(1)} {current_year}", "%b %d %H:%M:%S %Y")
                    except ValueError:
                        dt_obj = datetime.strptime(f"{match.group(1)} {current_year - 1}", "%b %d %H:%M:%S %Y")
                    return {"timestamp": dt_obj, "tcp_listen": int(match.group(2)), "tcp_established": int(match.group(3))}
            case _:
                return None
    except Exception as e:
        print(f"Error parsing log line: {e} for line: {line}")
        return None
@blueprint.route('/performance_charts')
@login_required
def performance_charts():
    # Lấy danh sách các IP nodes mà user có quyền manager
    manager_node_ips = []
    manager_user_nodes = UserNodes.query.filter_by(user_id=current_user.id, role='manager').all()
    for entry in manager_user_nodes:
        node = Nodes.query.get(entry.node_id)
        if node:
            manager_node_ips.append(node.ip_address)
    
    # Lấy các tham số từ request (khi user submit form)
    selected_ips = request.args.getlist('nodes')
    selected_ips = [ip.strip().rstrip('/') for ip in selected_ips] # <--- DÒNG QUAN TRỌNG
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # Xử lý ngày bắt đầu và kết thúc mặc định
    end_date = datetime.now()
    start_date = end_date - timedelta(days=10) # Mặc định 10 ngày trước

    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        except ValueError:
            flash("Ngày bắt đầu không hợp lệ. Sử dụng định dạng YYYY-MM-DD.", 'danger')
            start_date_str = start_date.strftime('%Y-%m-%d') # Reset to default for form
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            # Thêm 1 ngày để bao gồm toàn bộ ngày cuối cùng
            end_date = end_date + timedelta(days=1, seconds=-1) # Đến cuối ngày
        except ValueError:
            flash("Ngày kết thúc không hợp lệ. Sử dụng định dạng YYYY-MM-DD.", 'danger')
            end_date_str = end_date.strftime('%Y-%m-%d') # Reset to default for form

    # Nếu không có nodes nào được chọn, mặc định chọn tất cả các nodes mà user quản lý
    if not selected_ips:
        selected_ips = manager_node_ips
    print(f"DEBUG: Selected IPs after cleaning: {selected_ips}") # <-- Thêm dòng này
    base_log_dir = "/var/log/remote/"
    all_log_data = defaultdict(lambda: defaultdict(list)) # Structure: {ip: {cpu: [], disk: [], ...}}

    if not os.path.exists(base_log_dir):
        flash(f"Thư mục log từ xa '{base_log_dir}' không tồn tại.", 'warning')
        # Vẫn render template để hiện thị form chọn node
        return render_template(
            'home/performance_charts.html',
            chart_data={},
            available_nodes=manager_node_ips,
            selected_nodes=selected_ips,
            start_date_val=start_date.strftime('%Y-%m-%d'),
            end_date_val=end_date.strftime('%Y-%m-%d')
        )

    log_types = ["cpu", "disk", "network", "ram"]

    for client_ip_dir in os.listdir(base_log_dir):
        # Chỉ xử lý các nodes mà người dùng đã chọn
        if client_ip_dir not in selected_ips:
            print(f"DEBUG: Skipping {client_ip_dir} - not selected.")
            continue
        
        # Bỏ qua 127.0.0.1 và các thư mục không phải IP
        if client_ip_dir == '127.0.0.1' or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', client_ip_dir):
            print(f"DEBUG: Skipping {client_ip_dir} - not a valid IP or is localhost.")
            continue

        for log_type in log_types:
            log_path = os.path.join(base_log_dir, client_ip_dir, f"{log_type}.log")
            print(f"DEBUG: Checking log_path: {log_path}") # <-- Thêm dòng này
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r') as f:
                        for line_num, line in enumerate(f): # <-- Thêm enumerate để biết dòng nào
                            entry = parse_perf_log_line(line, log_type)
                            if entry is None:
                                print(f"DEBUG: Line {line_num+1} from {log_path} returned None from parse_perf_log_line.") # <-- Thêm dòng này
                            elif not (start_date <= entry['timestamp'] <= end_date):
                                print(f"DEBUG: Line {line_num+1} from {log_path} timestamp {entry['timestamp']} is out of range ({start_date} to {end_date}).") # <-- Thêm dòng này
                            else:
                                all_log_data[client_ip_dir][log_type].append(entry)
                                # print(f"DEBUG: Added entry from {log_path} for {client_ip_dir} {log_type}.") # <-- Bỏ comment để xem chi tiết
                except Exception as e:
                    print(f"ERROR: Reading log file {log_path}: {e}") # <-- Sử dụng ERROR để dễ thấy hơn
            else:
                print(f"DEBUG: Log file not found: {log_path}") # <-- Thêm dòng này
    print(f"\nDEBUG: Final all_log_data keys: {list(all_log_data.keys())}") # <-- Thêm dòng này
    # Process and aggregate data for Chartist.js
    chart_data_for_chartist = {}
    for ip, log_type_data in all_log_data.items():
        chart_data_for_chartist[ip] = {}
        for log_type, log_entries in log_type_data.items():
            # Sắp xếp entries theo timestamp
            log_entries.sort(key=lambda x: x['timestamp'])

            # Lấy timestamp đã được định dạng cho labels
            # Chú ý: Dòng này quan trọng để Chartist.js có thể hiển thị.
            # Bạn có thể điều chỉnh định dạng hiển thị cho dễ đọc hơn
            timestamps_formatted = [entry['timestamp'].strftime('%b %d %H:%M') for entry in log_entries]

            if log_type == "cpu":
                usage_values = [entry['cpu_usage'] for entry in log_entries]
                chart_data_for_chartist[ip][log_type] = {
                    "labels": timestamps_formatted,
                    "series": [usage_values]
                }
            elif log_type == "disk":
                 usage_values = [entry['root_usage'] for entry in log_entries]
                 chart_data_for_chartist[ip][log_type] = {
                    "labels": timestamps_formatted,
                    "series": [usage_values]
                 }
            elif log_type == "ram":
                used_ram_values = [entry['used_ram'] for entry in log_entries]
                chart_data_for_chartist[ip][log_type] = {
                    "labels": timestamps_formatted,
                    "series": [used_ram_values]
                }
            elif log_type == "network":
                tcp_listen_values = [entry['tcp_listen'] for entry in log_entries]
                tcp_established_values = [entry['tcp_established'] for entry in log_entries]
                chart_data_for_chartist[ip][log_type] = {
                    "labels": timestamps_formatted,
                    "series": [tcp_listen_values, tcp_established_values]
                }

    return render_template(
        'home/performance_charts.html',
        chart_data=chart_data_for_chartist,
        available_nodes=manager_node_ips, # Danh sách các node mà user có thể chọn
        selected_nodes=selected_ips,       # Các node đã được chọn từ form
        start_date_val=start_date.strftime('%Y-%m-%d'), # Giá trị ngày bắt đầu để hiển thị trong input
        end_date_val=(end_date - timedelta(days=1, seconds=-1)).strftime('%Y-%m-%d') # Giá trị ngày kết thúc hiển thị trong input
    )

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
import pexpect 
def run_ssh_copy_id(user, ip, password):
    """
    Executes the ssh-copy-id command with a password using pexpect.
    Returns (True, "Success message") or (False, "Error message").
    """
    command = f"ssh-copy-id {user}@{ip}"
    try:
        child = pexpect.spawn(command, encoding='utf-8', timeout=60)

        index = child.expect([
            "All keys were already added",                     # 0: Key already exists (clear message)
            "Number of key(s) added:        1",               # 1: Success (key added)
            "Number of key(s) added:        0",               # 2: Key not added, possibly due to already existing
            f"{user}@{ip}'s password:",                       # 3: Exact password prompt
            "password:",                                      # 4: Common password prompt
            "Password:",                                      # 5: Another common password prompt
            r"Are you sure you want to continue connecting \(yes/no\)\?", # 6: Host key prompt
            "Permission denied",                              # 7: Authentication error
            "password authentication failed",                 # 8: Authentication error
            pexpect.TIMEOUT,                                  # 9: Timeout
            pexpect.EOF                                       # 10: Command finished (handle last)
        ])

        # Get all output before the match for later inspection
        full_output_before_match = child.before.strip()
        
        # We will only check child.before at the necessary points.

        # --- Handle cases ---

        if index == 0: # "All keys were already added" (Clearly a success)
            return True, "SSH key already exists on the target server."
        
        elif index == 1: # "Number of key(s) added: 1" (Success)
            return True, "SSH key copied successfully."
        
        elif index == 2: # "Number of key(s) added: 0"
            if "All keys were skipped because they already exist on the remote system" in full_output_before_match or "already exists" in full_output_before_match.lower() or "not added" in full_output_before_match.lower():
                return True, "SSH key already exists on the target server."
            else:
                return False, f"ssh-copy-id added no keys: {full_output_before_match}"

        elif index in [3, 4, 5]: # Match password prompt
            child.sendline(password)
            final_index = child.expect([
                pexpect.TIMEOUT,
                "Number of key(s) added:        1",
                "All keys were already added",
                "Number of key(s) added:        0",
                "Permission denied",
                "password authentication failed",
                pexpect.EOF
            ])
            
            output_after_password = child.before.strip()

            if final_index in [1, 2]:
                return True, "SSH key copied successfully or already exists."
            elif final_index == 3:
                if "already exists" in output_after_password.lower() or "skipped" in output_after_password.lower() or "not added" in output_after_password.lower():
                    return True, "SSH key already exists on the target server (after password entry)."
                else:
                    return False, f"Could not copy key: {output_after_password}"
            elif final_index in [4, 5]:
                return False, f"Password authentication failed or denied: {output_after_password}"
            elif final_index == 0:
                return False, f"Timeout after sending password. Output: {output_after_password}"
            else: # EOF - command finished, check its output
                if "Number of key(s) added: 1" in output_after_password or "All keys were already added" in output_after_password or ("Number of key(s) added: 0" in output_after_password and ("already exists" in output_after_password.lower() or "skipped" in output_after_password.lower() or "not added" in output_after_password.lower())):
                    return True, "SSH key copied successfully or already exists."
                return False, f"Could not copy key: {output_after_password}"
        
        elif index == 6: # Host key not known (If this prompt appears)
            child.sendline("yes")
            sub_index = child.expect([
                pexpect.TIMEOUT,
                f"{user}@{ip}'s password:",
                "password:",
                "Password:",
                pexpect.EOF
            ])
            
            output_after_yes = child.before.strip()

            if sub_index == 0:
                return False, f"Timeout after confirming SSH host key. Final output: {output_after_yes}"
            elif sub_index in [1, 2, 3]: # Got password prompt
                child.sendline(password)
                final_index_after_yes_pass = child.expect([
                    pexpect.TIMEOUT,
                    "Number of key(s) added:        1",
                    "All keys were already added",
                    "Number of key(s) added:        0",
                    "Permission denied",
                    "password authentication failed",
                    pexpect.EOF
                ])
                output_after_final_pass = child.before.strip()
                if final_index_after_yes_pass in [1, 2]:
                    return True, "SSH key copied successfully or already exists."
                elif final_index_after_yes_pass == 3:
                     if "already exists" in output_after_final_pass.lower() or "skipped" in output_after_final_pass.lower() or "not added" in output_after_final_pass.lower():
                         return True, "SSH key already exists on the target server."
                     else:
                         return False, f"Could not copy key: {output_after_final_pass}"
                elif final_index_after_yes_pass in [4, 5]:
                    return False, f"Password authentication failed or denied: {output_after_final_pass}"
                elif final_index_after_yes_pass == 0:
                    return False, f"Timeout after sending password (after host confirmation). Output: {output_after_final_pass}"
                else: # EOF after password
                    if "Number of key(s) added: 1" in output_after_final_pass or "All keys were already added" in output_after_final_pass or ("Number of key(s) added: 0" in output_after_final_pass and ("already exists" in output_after_final_pass.lower() or "skipped" in output_after_final_pass.lower() or "not added" in output_after_final_pass.lower())):
                        return True, "SSH key copied successfully or already exists."
                    return False, f"Could not copy key: {output_after_final_pass}"
            
            elif sub_index == 4: # EOF after sending 'yes' - command finished immediately after accepting host key
                if "All keys were skipped because they already exist on the remote system" in output_after_yes or "already exists" in output_after_yes.lower() or "Number of key(s) added: 0" in output_after_yes or "not added" in output_after_yes.lower():
                    return True, "SSH key already exists on the target server (after host confirmation, early EOF)."
                return False, f"Could not copy key (after host confirmation, early EOF): {output_after_yes}"


        elif index in [7, 8]: # Permission denied / Auth failed (initial match)
            return False, f"Permission denied or authentication failed. Please check username and password. Output: {full_output_before_match}"
        
        elif index == 9: # pexpect.TIMEOUT (initial match)
            return False, f"Timeout while waiting for response. Output: {full_output_before_match}"

        elif index == 10: # pexpect.EOF (initial match - command terminated unexpectedly)
            # Check if previous output contains success/already exists message
            if "All keys were skipped because they already exist on the remote system" in full_output_before_match or "already exists" in full_output_before_match.lower() or "Number of key(s) added: 0" in full_output_before_match or "not added" in full_output_before_match.lower():
                return True, "SSH key already exists on the target server (early termination)."
            return False, f"ssh-copy-id terminated unexpectedly. Output: {full_output_before_match}"

        else: # Fallback for unexpected matches
            return False, f"Unexpected response from ssh-copy-id. Output: {full_output_before_match}"

    except pexpect.exceptions.ExceptionPexpect as e:
        # In case of a Pexpect error, child.before might still contain useful output
        return False, f"Pexpect error running ssh-copy-id: {e}. Output received: {child.before.strip() if 'child' in locals() else 'N/A'}"
    except Exception as e:
        # If a general Exception occurs, it might not be directly related to pexpect,
        # and 'child' might not be defined or in an unexpected state.
        # Ensure 'child' is defined before accessing child.before
        error_output = "N/A"
        if 'child' in locals() and hasattr(child, 'before') and child.before is not None:
             error_output = child.before.strip()
        return False, f"An unexpected error occurred running ssh-copy-id: {e}. Output received: {error_output}"

# Helper function to generate SSH keys
def generate_ssh_keys():
    """
    Generates an SSH key pair (~/.ssh/id_rsa and ~/.ssh/id_rsa.pub).
    Returns (True, "Success message", public_key_path) or (False, "Error message", None).
    """
    ssh_dir = os.path.expanduser("~/.ssh")
    private_key_path = os.path.join(ssh_dir, "id_rsa")
    public_key_path = os.path.join(ssh_dir, "id_rsa.pub")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return True, "SSH keys already exist.", public_key_path

    os.makedirs(ssh_dir, exist_ok=True)

    try:
        # Generate SSH keys without a passphrase for automation purposes
        result = subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", private_key_path, "-N", ""],
            capture_output=True,
            text=True,
            check=True # Raise exception for non-zero exit code
        )
        os.chmod(private_key_path, stat.S_IRUSR) # Set 0400 permissions for private key
        return True, f"SSH keys successfully generated: {public_key_path}", public_key_path
    except subprocess.CalledProcessError as e:
        # RETURN 3 VALUES HERE, ADD 'None' for public_key_path
        return False, f"Failed to generate SSH keys: {e.stderr.strip()}", None
    except Exception as e:
        # RETURN 3 VALUES HERE, ADD 'None' for public_key_path
        return False, f"An unexpected error occurred during key generation: {e}", None

@blueprint.route('/manage_nodes', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_nodes():
    if request.method == 'POST':
        if current_user.role != 'admin':
            flash("You do not have permission to perform this action.", 'danger')
            return redirect(url_for('home_blueprint.manage_nodes'))

        key_gen_success, key_gen_message, local_ssh_public_key_path = generate_ssh_keys()
        if not key_gen_success:
            flash(f"Error setting up local SSH key: {key_gen_message}. Cannot add/update node.", 'danger')
            return redirect(url_for('home_blueprint.manage_nodes'))
        else:
            flash(key_gen_message, 'info')

        if not local_ssh_public_key_path or not os.path.exists(local_ssh_public_key_path):
            flash("Local public SSH key not found. Cannot proceed.", 'danger')
            return redirect(url_for('home_blueprint.manage_nodes'))

        try:
            with open(local_ssh_public_key_path, 'r') as f:
                public_key_content_for_db = f.read().strip() # Variable name kept as per original logic, though not stored in DB
        except Exception as e:
            flash(f"Error reading local public SSH key: {e}", 'danger')
            return redirect(url_for('home_blueprint.manage_nodes'))

        num_forms = len([key for key in request.form.keys() if key.startswith('hostname_')])
        for i in range(num_forms):
            hostname = request.form.get(f'hostname_{i}').strip()
            ip_address = request.form.get(f'ip_address_{i}').strip()
            ssh_user = request.form.get(f'ssh_user_{i}').strip()
            password = request.form.get(f'password_{i}', '').strip()

            managers_for_node = list(map(int, request.form.getlist(f'managers_{i}')))
            viewers_for_node = list(map(int, request.form.getlist(f'viewers_{i}')))

            common_users = set(managers_for_node) & set(viewers_for_node)
            if common_users:
                common_usernames = [u.username for u in Users.query.filter(Users.id.in_(list(common_users))).all()]
                flash(f"Node '{hostname}': Users '{', '.join(common_usernames)}' cannot be both a manager and a viewer for this node.", 'danger')
                continue

            if Nodes.query.filter_by(hostname=hostname).first():
                flash(f"Hostname '{hostname}' already exists.", 'danger')
                continue
            if Nodes.query.filter_by(ip_address=ip_address).first():
                flash(f"IP '{ip_address}' already exists.", 'danger')
                continue

            # --- Simplified SSH Key Copy Logic ---
            ssh_copy_id_succeeded = True # Assume success by default
            if password:
                flash(f"Attempting to copy SSH key to {ssh_user}@{ip_address}...", 'info')
                success, message = run_ssh_copy_id(ssh_user, ip_address, password)

                # Check for success messages or key already exists messages
                if not success:
                    # Check if the error is due to the key already existing
                    if "All keys were already added" in message or "already exists" in message.lower() or "Number of key(s) added: 0" in message:
                        flash(f"SSH key already exists on {ssh_user}@{ip_address}: {message}", 'warning')
                        ssh_copy_id_succeeded = True # Still consider it a success to proceed
                    else:
                        flash(f"Could not copy SSH key to {ssh_user}@{ip_address}: {message}", 'danger')
                        ssh_copy_id_succeeded = False # Serious error, do not add node
                else: # if success is True, flash the success message from run_ssh_copy_id
                    flash(f"SSH key operation for {ssh_user}@{ip_address}: {message}", 'success') # Added success message here

            else:
                flash(f"No password provided to set up SSH key for {hostname}. Assuming key is already set up or will be done manually.", 'warning')
                # If no password, we still consider it a success and proceed
            
            if not ssh_copy_id_succeeded:
                continue # If ssh-copy-id failed critically, skip this node

            # --- Node addition logic remains unchanged ---
            node = Nodes(hostname=hostname,
                         ip_address=ip_address,
                         ssh_user=ssh_user)
            db.session.add(node)
            db.session.commit()

            for uid in managers_for_node:
                db.session.add(UserNodes(user_id=uid, node_id=node.id, role='manager'))
            for uid in viewers_for_node:
                db.session.add(UserNodes(user_id=uid, node_id=node.id, role='viewer'))
            db.session.commit()

            flash(f"Node '{hostname}' created successfully.", 'success')

        return redirect(url_for('home_blueprint.manage_nodes'))

    nodes = Nodes.query.options(
        joinedload(Nodes.user_nodes).joinedload(UserNodes.user)
    ).all()
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
    key_gen_success, key_gen_message, local_ssh_public_key_path = generate_ssh_keys()
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
    # Lấy tất cả các node mà người dùng hiện tại có quyền (viewer hoặc manager)
    user_nodes_entries = UserNodes.query.filter_by(user_id=current_user.id).all()
    
    node_ids = [un.node_id for un in user_nodes_entries]
    nodes = Nodes.query.filter(Nodes.id.in_(node_ids)).all()

    # Tạo một dictionary để lưu thông tin node, bao gồm vai trò của người dùng
    # Ví dụ: {node_id: {'object': node_obj, 'role': 'manager/viewer'}}
    nodes_with_roles = {}
    for entry in user_nodes_entries:
        node_obj = next((n for n in nodes if n.id == entry.node_id), None)
        if node_obj:
            nodes_with_roles[node_obj.id] = {
                'object': node_obj,
                'role': entry.role # Lưu vai trò của user trên node này
            }

    status = {}
    for node_entry in nodes_with_roles.values():
        node = node_entry['object']
        status[node.id] = {}
        for chain in ['INPUT','OUTPUT','FORWARD']:
            cmd = f"sudo iptables -L {chain} --line-numbers -n"
            res = run_ssh_on_node(node, cmd)
            if res.returncode == 0:
                status[node.id][chain] = parse_iptables_output(res.stdout)
            else:
                flash(f"Không thể lấy trạng thái IPTables từ {node.hostname} chain {chain}: {res.stderr}", 'warning')
                status[node.id][chain] = [] # Trả về list rỗng nếu có lỗi

    # Truyền nodes_with_roles thay vì chỉ nodes
    return render_template('home/view_status.html', nodes_with_roles=nodes_with_roles, status=status)

@blueprint.route('/delete_rule', methods=['POST'])
@login_required
def delete_rule():
    """
    Xóa luật IPTables trên node. Nhận dữ liệu qua POST.
    """
    try:
        nid = request.form.get('node_id', type=int) # Lấy từ request.form
        chain = request.form.get('chain_name', '').upper() # Lấy từ request.form
        rn = request.form.get('rule_index', type=int) # Lấy từ request.form
    except Exception as e:
        flash(f'Invalid parameters: {e}', 'danger')
        return redirect(url_for('home_blueprint.view_status'))

    # Kiểm tra quyền hạn của người dùng (đã được xử lý bởi @role_required,
    # nhưng vẫn có thể giữ kiểm tra này như một lớp bảo vệ bổ sung nếu cần)
    user_node_role = UserNodes.query.filter_by(
        user_id=current_user.id,
        node_id=nid
    ).first()

    # Thêm kiểm tra vai trò cụ thể ở đây nếu decorator role_required không đủ chi tiết
    # Ví dụ: nếu admin không có entry trong UserNodes cho node này nhưng vẫn có quyền
    if not user_node_role or user_node_role.role not in ['manager', 'admin']:
        flash('You do not have permission to delete rules on this node.', 'danger')
        return redirect(url_for('home_blueprint.view_status'))

    node = Nodes.query.get_or_404(nid)

    # Lệnh xóa luật IPTables
    cmd_delete = f"sudo iptables -D {chain} {rn}"
    res_delete = run_ssh_on_node(node, cmd_delete)

    if res_delete.returncode != 0:
        flash(f"Error deleting rule {rn} from chain {chain} on {node.hostname}: {res_delete.stderr}", 'danger')
    flash("Successfully deleted rule")
    return redirect(url_for('home_blueprint.view_status'))