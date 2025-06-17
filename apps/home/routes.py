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
    # Sử dụng dictionary để lưu trữ thông tin node_id và node_ip theo client_ip_dir
    # user_allowed_nodes_info = { "ip_address": {"node_id": X, "node_ip": "Y"} }
    user_allowed_nodes_info = {}
    
    node_entries = UserNodes.query.filter_by(user_id=current_user.id).all()
    for entry in node_entries:
        node = Nodes.query.get(entry.node_id)
        if node:
            # Lưu trữ thông tin node vào dictionary
            user_allowed_nodes_info[node.ip_address] = {
                'node_id': node.id,
                'node_ip': node.ip_address
            }
    base_log_dir = "/var/log/remote/"
    all_entries = []

    if not os.path.exists(base_log_dir):
        flash(f"Thư mục log từ xa '{base_log_dir}' không tồn tại.", 'warning')
        return render_template('home/view_log.html', log_entries=[])

    # Duyệt qua các thư mục con trong /var/log/remote (mỗi thư mục là một IP client)
    for client_ip_dir in os.listdir(base_log_dir):
        # Bỏ qua các IP không hợp lệ hoặc localhost
        if client_ip_dir == '127.0.0.1' or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', client_ip_dir):
            continue

        # Chỉ xử lý các IP mà người dùng hiện tại có quyền truy cập
        if client_ip_dir not in user_allowed_nodes_info:
            continue

        # Lấy thông tin node từ dictionary đã chuẩn bị sẵn
        current_node_info = user_allowed_nodes_info[client_ip_dir]
        node_id_for_log = current_node_info['node_id']
        node_ip_for_log = current_node_info['node_ip']

        iptables_log_path = os.path.join(base_log_dir, client_ip_dir, "iptables.log")
        
        if os.path.exists(iptables_log_path):

            try:
                with open(iptables_log_path, 'r') as f:
                    for line in f:
                        entry = parse_log_line(line)
                        # Chỉ xử lý nếu parse_log_line trả về một dictionary không rỗng
                        if entry:
                            # Thêm node_id và node_ip vào dictionary 'entry'
                            # Lưu ý: thứ tự thêm vào dictionary không ảnh hưởng đến thứ tự hiển thị
                            # trong template, nhưng bạn có thể kiểm soát nó bằng cách tạo một dict mới
                            # hoặc sắp xếp lại các khóa nếu muốn.
                            
                            # Cách 1: Thêm trực tiếp vào dictionary đã parse
                            entry['node_id'] = node_id_for_log
                            entry['node_ip'] = node_ip_for_log
                            all_entries.append(entry)

                            # Cách 2 (Nếu bạn muốn kiểm soát chính xác thứ tự các key trong dict):
                            # Bạn có thể tạo một OrderedDict hoặc tạo dict mới theo thứ tự mong muốn
                            # new_entry = {
                            #     'timestamp': entry.get('timestamp', ''),
                            #     'node_id': node_id_for_log,
                            #     'node_ip': node_ip_for_log,
                            #     'hostname': entry.get('hostname', ''),
                            #     # ... thêm các trường khác theo thứ tự bạn muốn ...
                            # }
                            # all_entries.append(new_entry)
            except Exception as e:
                flash(f"Lỗi khi đọc file log {iptables_log_path}: {e}", 'error')
        else:
            flash(f"File '{iptables_log_path}' không tồn tại.", 'info')

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
    selected_ips = request.args.getlist('nodes') # 'nodes' là tên của checkbox group
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
            continue
        
        # Bỏ qua 127.0.0.1 và các thư mục không phải IP
        if client_ip_dir == '127.0.0.1' or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', client_ip_dir):
            continue

        for log_type in log_types:
            log_path = os.path.join(base_log_dir, client_ip_dir, f"{log_type}.log")
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r') as f:
                        for line in f:
                            entry = parse_perf_log_line(line, log_type)
                            if entry and start_date <= entry['timestamp'] <= end_date:
                                all_log_data[client_ip_dir][log_type].append(entry)
                except Exception as e:
                    print(f"Error reading log file {log_path}: {e}")

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
    Thực thi lệnh ssh-copy-id với mật khẩu sử dụng pexpect.
    Trả về (True, "Thông báo thành công") hoặc (False, "Thông báo lỗi").
    """
    command = f"ssh-copy-id {user}@{ip}"
    try:
        # Tăng timeout lên 60 giây để đảm bảo đủ thời gian cho phản hồi
        child = pexpect.spawn(command, encoding='utf-8', timeout=60)

        # Danh sách các mẫu mà chúng ta mong đợi từ ssh-copy-id.
        # Thêm mẫu prompt mật khẩu chính xác bạn đã thấy.
        index = child.expect([
            pexpect.TIMEOUT,
            r"Are you sure you want to continue connecting \(yes/no\)\?", # Host key prompt (có thể xuất hiện)
            f"{user}@{ip}'s password:",      # <-- THAY ĐỔI QUAN TRỌNG: Mẫu mật khẩu chính xác
            "password:",                     # Mẫu mật khẩu phổ biến
            "Password:",                     # Mẫu mật khẩu phổ biến khác
            "Number of key(s) added:        1", # Thành công
            "All keys were already added",   # Thành công (key đã tồn tại)
            "Number of key(s) added:        0", # Có thể thành công (nếu key đã tồn tại)
            "Permission denied",             # Lỗi xác thực
            "password authentication failed", # Lỗi xác thực
            pexpect.EOF                      # Kết thúc lệnh
        ])

        # --- Xử lý các trường hợp ---

        if index == 0: # TIMEOUT
            return False, f"Timeout khi cố gắng sao chép SSH key. Output cuối: {child.before.strip()}"
        
        elif index == 1: # Host key not known (Nếu prompt này xuất hiện)
            child.sendline("yes")
            # Sau khi gửi 'yes', chúng ta lại chờ prompt mật khẩu hoặc kết thúc
            sub_index = child.expect([
                pexpect.TIMEOUT,
                f"{user}@{ip}'s password:", # <-- THAY ĐỔI QUAN TRỌNG Ở ĐÂY CŨNG VẬY
                "password:",
                "Password:",
                pexpect.EOF
            ])
            
            if sub_index == 0:
                return False, f"Timeout sau khi xác nhận khóa host SSH. Output cuối: {child.before.strip()}"
            elif sub_index in [1, 2, 3]: # Got password prompt
                child.sendline(password)
            elif sub_index == 4: # EOF after sending 'yes' - command finished
                output = child.before.strip()
                if "Number of key(s) added: 1" in output or "All keys were already added" in output or ("Number of key(s) added: 0" in output and "already exists" in output.lower()):
                    return True, "SSH key đã được sao chép thành công hoặc đã tồn tại (sau xác nhận host)."
                return False, f"Không thể sao chép key (sau xác nhận host, EOF): {output}"

        # Nếu ban đầu đã khớp với prompt mật khẩu
        if index in [2, 3, 4]: # Các mẫu mật khẩu
            child.sendline(password)
            # Chờ kết quả cuối cùng sau khi gửi mật khẩu
            final_index = child.expect([
                pexpect.TIMEOUT,
                "Number of key(s) added:        1",
                "All keys were already added",
                "Number of key(s) added:        0",
                "Permission denied",
                "password authentication failed",
                pexpect.EOF
            ])

            output = child.before.strip()
            
            if final_index in [1, 2]: # Key added or already added
                return True, "SSH key đã được sao chép thành công hoặc đã tồn tại."
            elif final_index == 3: # Number of keys added: 0 - check if it means already exists
                if "already exists" in output.lower() or "not added" in output.lower():
                    return True, "SSH key đã tồn tại trên máy chủ đích."
                else:
                    return False, f"Không thể sao chép key: {output}"
            elif final_index in [4, 5]: # Permission denied / Auth failed
                return False, f"Xác thực mật khẩu không thành công hoặc bị từ chối: {output}"
            elif final_index == 0: # Timeout after password
                return False, f"Timeout sau khi gửi mật khẩu. Output: {output}"
            else: # EOF - command finished, check its output
                if "Number of key(s) added: 1" in output or "All keys were already added" in output or ("Number of key(s) added: 0" in output and "already exists" in output.lower()):
                    return True, "SSH key đã được sao chép thành công hoặc đã tồn tại."
                return False, f"Không thể sao chép key: {output}"

        # Các trường hợp đã khớp với thông báo thành công ban đầu hoặc lỗi ban đầu
        elif index in [5, 6]: # Key already added or successfully added (initial match)
            return True, "SSH key đã được sao chép thành công hoặc đã tồn tại."
        elif index == 7: # Number of keys added: 0 - initial match, check if it means already exists
            output = child.before.strip()
            if "already exists" in output.lower() or "not added" in output.lower() or child.after.strip() == "": 
                 return True, "SSH key đã tồn tại trên máy chủ đích."
            else:
                 return False, f"Không thể sao chép key: {output}"
        elif index in [8, 9]: # Permission denied / Auth failed (initial match)
            return False, f"Quyền bị từ chối hoặc xác thực thất bại. Vui lòng kiểm tra tên người dùng và mật khẩu. Output: {child.before.strip()}"
        elif index == 10: # EOF unexpected
            return False, f"ssh-copy-id kết thúc đột ngột. Output: {child.before.strip()}"
        else: # Fallback for unexpected matches
            return False, f"Phản hồi không mong muốn từ ssh-copy-id. Output: {child.before.strip()}"

    except pexpect.exceptions.ExceptionPexpect as e:
        return False, f"Lỗi Pexpect khi chạy ssh-copy-id: {e}. Child output before error: {child.before.strip() if 'child' in locals() else 'N/A'}"
    except Exception as e:
        return False, f"Lỗi không mong muốn khi chạy ssh-copy-id: {e}"
# Helper function to generate SSH keys
def generate_ssh_keys():
    """
    Tạo cặp khóa SSH private và public (~/.ssh/id_rsa và ~/.ssh/id_rsa.pub).
    Trả về (True, "Thông báo thành công", public_key_path) hoặc (False, "Thông báo lỗi", None).
    """
    ssh_dir = os.path.expanduser("~/.ssh")
    private_key_path = os.path.join(ssh_dir, "id_rsa")
    public_key_path = os.path.join(ssh_dir, "id_rsa.pub")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return True, "SSH keys đã tồn tại.", public_key_path

    os.makedirs(ssh_dir, exist_ok=True)

    try:
        # Tạo SSH keys không có passphrase cho mục đích tự động hóa
        result = subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", private_key_path, "-N", ""],
            capture_output=True,
            text=True,
            check=True # Raise exception cho mã thoát khác 0
        )
        os.chmod(private_key_path, stat.S_IRUSR) # Đặt quyền 0400 cho private key
        return True, f"SSH keys đã được tạo thành công: {public_key_path}", public_key_path
    except subprocess.CalledProcessError as e:
        # TRẢ VỀ 3 GIÁ TRỊ Ở ĐÂY, THÊM 'None' CHO public_key_path
        return False, f"Không thể tạo SSH keys: {e.stderr.strip()}", None
    except Exception as e:
        # TRẢ VỀ 3 GIÁ TRỊ Ở ĐÂY, THÊM 'None' CHO public_key_path
        return False, f"Một lỗi không mong muốn đã xảy ra trong quá trình tạo khóa: {e}", None
@blueprint.route('/manage_nodes', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_nodes():
    if request.method == 'POST':
        if current_user.role != 'admin':
            flash("Bạn không có quyền thực hiện thao tác này.", 'danger')
            return redirect(url_for('home_blueprint.manage_nodes'))

        key_gen_success, key_gen_message, local_ssh_public_key_path = generate_ssh_keys()
        if not key_gen_success:
            flash(f"Lỗi thiết lập SSH key cục bộ: {key_gen_message}. Không thể thêm/cập nhật node.", 'danger')
            return redirect(url_for('home_blueprint.manage_nodes'))
        else:
            flash(key_gen_message, 'info')

        if not local_ssh_public_key_path or not os.path.exists(local_ssh_public_key_path):
            flash("Không tìm thấy public SSH key cục bộ. Không thể tiếp tục.", 'danger')
            return redirect(url_for('home_blueprint.manage_nodes'))

        try:
            with open(local_ssh_public_key_path, 'r') as f:
                public_key_content_for_db = f.read().strip()
        except Exception as e:
            flash(f"Lỗi khi đọc public SSH key: {e}", 'danger')
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
                flash(f"Node '{hostname}': Người dùng '{', '.join(common_usernames)}' không thể vừa là người quản lý vừa là người xem cho node này.", 'danger')
                continue

            if Nodes.query.filter_by(hostname=hostname).first():
                flash(f"Hostname '{hostname}' đã tồn tại.", 'danger')
                continue
            if Nodes.query.filter_by(ip_address=ip_address).first():
                flash(f"IP '{ip_address}' đã tồn tại.", 'danger')
                continue

            # --- Logic Sao chép SSH Key Đơn giản hơn ---
            ssh_copy_id_succeeded = True # Mặc định coi là thành công
            if password:
                flash(f"Đang cố gắng sao chép SSH key đến {ssh_user}@{ip_address}...", 'info')
                success, message = run_ssh_copy_id(ssh_user, ip_address, password)

                # Kiểm tra thông báo thành công hoặc thông báo key đã tồn tại
                # Giả sử run_ssh_copy_id trả về thông báo cụ thể cho trường hợp này
                if not success:
                    # Kiểm tra xem lỗi có phải do key đã tồn tại hay không
                    # Thêm các chuỗi bạn muốn chấp nhận là "thành công" vào đây
                    # ví dụ: "All keys were already added", "already exists"
                    if "All keys were already added" in message or "already exists" in message.lower() or "Number of key(s) added: 0" in message:
                        flash(f"SSH key đã tồn tại trên {ssh_user}@{ip_address}: {message}", 'warning')
                        ssh_copy_id_succeeded = True # Vẫn coi là thành công để tiếp tục
                    else:
                        flash(f"Không thể sao chép SSH key đến {ssh_user}@{ip_address}: {message}", 'danger')
                        ssh_copy_id_succeeded = False # Lỗi nghiêm trọng, không thêm node
            else:
                flash(f"Không có mật khẩu được cung cấp để thiết lập SSH key cho {hostname}. Giả sử key đã được thiết lập hoặc sẽ được thực hiện thủ công.", 'warning')
                # Nếu không có mật khẩu, chúng ta vẫn coi là thành công và tiếp tục
            
            if not ssh_copy_id_succeeded:
                continue # Nếu ssh-copy-id thất bại nghiêm trọng, bỏ qua node này

            # --- Logic thêm node vẫn giữ nguyên ---
            node = Nodes(hostname=hostname,
                         ip_address=ip_address,
                         ssh_user=ssh_user,
                         ssh_key=public_key_content_for_db)
            db.session.add(node)
            db.session.commit()

            for uid in managers_for_node:
                db.session.add(UserNodes(user_id=uid, node_id=node.id, role='manager'))
            for uid in viewers_for_node:
                db.session.add(UserNodes(user_id=uid, node_id=node.id, role='viewer'))
            db.session.commit()

            flash(f"Đã tạo Node '{hostname}'.", 'success')

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
            cmd = f"sudo iptables -L {chain} --line-numbers"
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
    return redirect(url_for('home_blueprint.view_status'))