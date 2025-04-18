# -*- encoding: utf-8 -*-
from apps.home import blueprint
from flask import render_template, request, flash, redirect, url_for
from flask_login import login_required
from jinja2 import TemplateNotFound
import subprocess
import re
import shlex
import html
import matplotlib.pyplot as plt
from collections import Counter
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Log messages of level DEBUG and above
    format='%(asctime)s [%(levelname)s] %(message)s',  # Log message format
    handlers=[logging.StreamHandler()]  # Log to the console
)

sudo_password = '123456'
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
#function to add rule to the INPUT chain in iptables
@blueprint.route('/add_rule', methods=['GET', 'POST'])
@login_required
def add_rule():
    error_message = ""
    if request.method == 'POST':
        manual_rule = request.form.get('manual_rule')
        if manual_rule:
            if validate_iptables_command(manual_rule):
                try:
                    command = f"echo {sudo_password} | {manual_rule}"
                    subprocess.run(command, shell=True, check=True)
                    flash('Rule added successfully!', 'success')
                except subprocess.CalledProcessError as e:
                    error_message = e.stderr.decode('utf-8') if e.stderr else str(e)
                    flash(f"An error occurred while adding the rule: {error_message}", 'danger')
            else:
                error_message = 'Invalid iptables command.'
                flash(error_message, 'danger')
            return redirect(url_for('home_blueprint.add_rule'))

        chains = request.form.getlist('chain[]')
        targets = request.form.getlist('target[]')
        prots = request.form.getlist('prot[]')
        sources = request.form.getlist('source[]')
        destinations = request.form.getlist('destination[]')
        sports = request.form.getlist('sport[]')
        dports = request.form.getlist('dport[]')

        if not chains and not manual_rule:
            flash('Please fill out either the Normal Rule form or the Manual Rule form.', 'danger')
            return redirect(url_for('home_blueprint.add_rule'))

        for chain, target, prot, source, destination, sport, dport in zip(chains, targets, prots, sources, destinations, sports, dports):
            # Sanitize inputs to prevent XSS, SQLi, etc.
            chain = sanitize_input(chain)
            target = sanitize_input(target).upper()
            prot = sanitize_input(prot)
            source = sanitize_input(source)
            destination = sanitize_input(destination)
            sport = sanitize_input(sport)
            dport = sanitize_input(dport)
            #craft the command based on the empty fields
            command = "echo {} | sudo -S iptables -A {} -j {} -p {} -s {} -d {} {} {}".format(
                sudo_password, chain, target, prot, source, destination, 
                f'--sport {sport}' if sport else '', f'--dport {dport}' if dport else ''
            )

            # Add the rule to iptables
            try:
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, check=True)
            
                if result.stderr:
                    error_message = result.stderr.decode('utf-8')
                    flash(f"An error occurred while adding the rule: {error_message}", 'danger')
                    return redirect(url_for('home_blueprint.add_rule'))
            except subprocess.CalledProcessError as e:
                error_message = e.stderr.decode('utf-8')
                flash(f"An error occurred while adding the rule: {error_message}", 'danger')
                return redirect(url_for('home_blueprint.add_rule'))

        #show a success message
        flash('Rule added successfully!', 'success')
        return redirect(url_for(f'home_blueprint.{chain.lower()}_status'))

    return render_template('home/add_rule.html', error_message=error_message)

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

@blueprint.route('/delete_rule')
@login_required
def delete_rule():
    chain = request.args.get('chain')
    rule_number = int(request.args.get('rule_number'))

    if not is_valid_chain(chain) or not is_valid_rule_number(rule_number):
        flash('Invalid chain or rule number.', 'danger')
        return redirect(url_for(f'home_blueprint.{chain.lower()}_status'))

    # Check if the rule is a logging rule
    command = "echo {} | sudo -S iptables -L {} --line-numbers".format(sudo_password, chain)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
    output, _ = process.communicate()
    output = output.decode('utf-8')
    lines = output.split('\n')
    rule_line = lines[rule_number]

    if rule_number == 1 and 'LOG' in rule_line:
        flash('Cannot delete the logging rule.', 'danger')
        return redirect(url_for(f'home_blueprint.{chain.lower()}_status'))

    try:
        # Delete the rule
        command = "echo {} | sudo -S iptables -D {} {}".format(sudo_password, chain, rule_number)
        subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)

    except subprocess.CalledProcessError as e:
        flash(f"An error occurred while deleting the rule: {e}", 'danger')
        return redirect(url_for(f'home_blueprint.{chain.lower()}_status'))

    flash('Rule deleted successfully!', 'success')
    return redirect(url_for(f'home_blueprint.{chain.lower()}_status'))
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



