#!/usr/bin/python3
# -*- coding: utf-8 -*-
# vim: ts=4
###
#
# Copyright (c) 2012 Mehdi Abaakouk
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
###

import base64
from datetime import datetime
import memcache
import subprocess
import logging
from logging.handlers import TimedRotatingFileHandler
import re
from urllib.request import urlopen
from urllib.parse import quote, unquote
import json
import random

from toolbox import mask_is_valid, ip_is_valid, ipv6_is_valid, ipv4_is_valid, resolve, resolve_any, save_cache_pickle, load_cache_pickle, unescape
#from xml.sax.saxutils import escape


import pydot
from flask import Flask, render_template, jsonify, redirect, session, request, abort, Response, Markup

app = Flask(__name__)
app.config.from_pyfile('lg.cfg')
app.secret_key = app.config["SESSION_KEY"]
app.debug = app.config["DEBUG"]

file_handler = TimedRotatingFileHandler(filename=app.config["LOG_FILE"], when="midnight")
file_handler.setLevel(getattr(logging, app.config["LOG_LEVEL"].upper()))
app.logger.addHandler(file_handler)

memcache_server = app.config.get("MEMCACHE_SERVER", "127.0.0.1:11211")
memcache_expiration = int(app.config.get("MEMCACHE_EXPIRATION", "1296000")) # 15 days by default
mc = memcache.Client([memcache_server])

def get_asn_from_as(n):
    asn_zone = app.config.get("ASN_ZONE", False)
    # don't generate spurious (and potentially slow) lookups if ASN_ZONE not defined in config
    if asn_zone:
        try:
            data = resolve("AS%s.%s" % (n, asn_zone) ,"TXT").replace("'","").replace('"','')
        except:
            return False
        return [ field.strip() for field in data.split("|") ]
    else:
        return False

def add_links(text):
    """Browser a string and replace ipv4, ipv6, as number, with a
    whois link """

    if type(text) in [str, str]:
        text = text.split("\n")

    ret_text = []
    for line in text:
        # Some heuristic to create link
        if line.strip().startswith("BGP.as_path:") or \
            line.strip().startswith("Neighbor AS:"):
            ret_text.append(re.sub(r'(\d+)', r'<a href="/whois?q=\1" class="whois">\1</a>', line))
        else:
            line = re.sub(r'([a-zA-Z0-9\-]*\.([a-zA-Z]{2,3}){1,2})(\s|$)', r'<a href="/whois?q=\1" class="whois">\1</a>\3', line)
            line = re.sub(r'(?<=\[)AS(\d+)', r'<a href="/whois?q=\1" class="whois">AS\1</a>', line)
            line = re.sub(r'(\d+\.\d+\.\d+\.\d+)', r'<a href="/whois?q=\1" class="whois">\1</a>', line)
            if len(request.path) >= 2:
                hosts = "/".join(request.path.split("/")[2:])
            else:
                hosts = "/"
            line = re.sub(r'\[(\w+)\s+((|\d\d\d\d-\d\d-\d\d\s)(|\d\d:)\d\d:\d\d|\w\w\w\d\d)', r'[<a href="/detail/%s?q=\1">\1</a> \2' % hosts, line)
            line = re.sub(r'(^|\s+)(([a-f\d]{0,4}:){3,10}[a-f\d]{0,4})', r'\1<a href="/whois?q=\2" class="whois">\2</a>', line, re.I)
            ret_text.append(line)
    return "\n".join(ret_text)


def set_session(request_type, hosts, proto, request_args):
    """ Store all data from user in the user session """
    session.permanent = True
    session.update({
        "request_type": request_type,
        "hosts": hosts,
        "proto": proto,
        "request_args": request_args,
    })
    history = session.get("history", [])

    # erase old format history
    if type(history) != type(list()):
        history = []

    t = (hosts, proto, request_type, request_args)
    if t in history:
        del history[history.index(t)]
    history.insert(0, t)
    session["history"] = history[:20]


def whois_command(query):
    server = []
    if app.config.get("WHOIS_SERVER", ""):
        server = [ "-h", app.config.get("WHOIS_SERVER") ]
    return subprocess.Popen(['whois'] + server + [query], stdout=subprocess.PIPE).communicate()[0].decode('utf-8', 'ignore')


def bird_command(host, proto, query):
    """Alias to bird_proxy for bird service"""
    if app.config.get("UNIFIED_DAEMON", False):
        return bird_proxy(host, app.config.get("PROTO_DEFAULT", "ipv4"), "bird", query)
    else:
        return bird_proxy(host, proto, "bird", query)


def bird_proxy(host, proto, service, query):
    """Retreive data of a service from a running lgproxy on a remote node

    First and second arguments are the node and the port of the running lgproxy
    Third argument is the service, can be "traceroute" or "bird"
    Last argument, the query to pass to the service

    return tuple with the success of the command and the returned data
    """

    path = ""
    if proto == "ipv6":
        path = service + "6"
    elif proto == "ipv4":
        path = service

    proxyHost = app.config["PROXY"].get(host, "")
    if isinstance(proxyHost, int):
        proxyHost = "%s:%s" % (host, proxyHost)

    if not proxyHost:
        return False, 'Host "%s" invalid' % host
    elif not path:
        return False, 'Proto "%s" invalid' % proto
    else:
        url = "http://%s/%s?q=%s" % (proxyHost, path, quote(query))
        proxy_timeout = app.config["PROXY_TIMEOUT"].get(service, 60)

        try:
            f = urlopen(url, None, proxy_timeout)
            resultat = f.read().decode('utf-8')
            status = True                # retreive remote status
        except IOError:
            resultat = "Failed retreive url: %s" % url
            status = False
        return status, resultat


@app.context_processor
def inject_commands():
    commands = [
            ("traceroute", "traceroute ..."),
            ("summary", "show protocols"),
            ("detail", "show protocols ... all"),
            ("prefix", "show route for ..."),
            ("prefix_detail", "show route for ... all"),
            ("prefix_bgpmap", "show route for ... (bgpmap)"),
            ("where", "show route where net ~ [ ... ]"),
            ("where_detail", "show route where net ~ [ ... ] all"),
            ("where_bgpmap", "show route where net ~ [ ... ] (bgpmap)"),
            ("adv", "show route ..."),
            ("adv_bgpmap", "show route ... (bgpmap)"),
        ]
    commands_dict = {}
    for id, text in commands:
        commands_dict[id] = text
    return dict(commands=commands, commands_dict=commands_dict)

@app.context_processor
def inject_all_host():
    return dict(all_hosts="+".join(list(app.config["PROXY"].keys())))

@app.route("/")
def hello():
    if app.config.get("UNIFIED_DAEMON", False):
        return redirect("/summary/all")
    else:
        return redirect("/summary/all/%s" % app.config.get("PROTO_DEFAULT", "ipv4"))

def error_page(text):
    return render_template('error.html', errors=[text]), 500


@app.errorhandler(400)
def incorrect_request(e):
        return render_template('error.html', warnings=["The server could not understand the request"]), 400


@app.errorhandler(404)
def page_not_found(e):
        return render_template('error.html', warnings=["The requested URL was not found on the server."]), 404

def get_query():
    q = unquote(request.args.get('q', '').strip())
    return q

@app.route("/whois")
def whois():
    query = get_query()
    if not query:
        abort(400)

    try:
        asnum = int(query)
        query = "as%d" % asnum
    except:
        m = re.match(r"[\w\d-]*\.(?P<domain>[\d\w-]+\.[\d\w-]+)$", query)
        if m:
            query = query.groupdict()["domain"]

    output = whois_command(query).replace("\n", "<br>")
    return jsonify(output=output, title=query)

# Array of protocols that will be filtered from the summary listing
SUMMARY_UNWANTED_PROTOS = ["Kernel", "Static", "Device", "BFD", "Direct", "RPKI"]
# Array of regular expressions to match against protocol names,
# and filter them from the summary view
SUMMARY_UNWANTED_NAMES = []

COMBINED_UNWANTED_NAMES = None
if len(SUMMARY_UNWANTED_NAMES) > 0 :  # If regex list is not empty
    # combine the unwanted names to a single regex
    COMBINED_UNWANTED_NAMES = '(?:%s)' % '|'.join(SUMMARY_UNWANTED_NAMES)

@app.route("/summary/<hosts>")
@app.route("/summary/<hosts>/<proto>")
def summary(hosts, proto="ipv4"):
    set_session("summary", hosts, proto, "")
    command = "show protocols"

    summary = {}
    errors = []
    hosts = hosts.split("+")
    if hosts == ["all"]:
        hosts = app.config["PROXY"].keys()
    for host in hosts:
        ret, res = bird_command(host, proto, command)
        res = res.split("\n")

        if ret is False:
            errors.append("%s" % res)
            continue

        if len(res) <= 1:
            errors.append("%s: bird command failed with error, %s" % (host, "\n".join(res)))
            continue

        data = []
        for line in res[1:]:
            line = line.strip()
            if line:
                split = line.split()
                if (
                        len(split) >= 5 and
                        split[1] not in SUMMARY_UNWANTED_PROTOS and
                        (COMBINED_UNWANTED_NAMES is None or not re.match(COMBINED_UNWANTED_NAMES, split[0])) # If the list is empty or doesn't match the protocol name
                   ):
                    props = dict()
                    props["name"] = split[0]
                    props["proto"] = split[1]
                    props["table"] = split[2]
                    props["state"] = split[3]
                    props["since"] = split[4]

                    if len(split) > 5:
                        # if bird is configured for 'timeformat protocol iso long'
                        # then the 5th column contains the time, rather than info
                        match = re.match(r'\d\d:\d\d:\d\d', split[5])
                        if match:
                            props["info"] = ' '.join(split[6:]) if len(split) > 6 else ""
                        else:
                            props["info"] = ' '.join(split[5:])
                    else:
                        props["info"] = ""
                        
                    data.append(props)

        summary[host] = data

    return render_template('summary.html', summary=summary, command=command, errors=errors)


@app.route("/detail/<hosts>")
@app.route("/detail/<hosts>/<proto>")
def detail(hosts, proto="ipv4"):
    name = get_query()

    if not name:
        abort(400)

    set_session("detail", hosts, proto, name)
    command = "show protocols all %s" % name

    detail = {}
    errors = []
    hosts = hosts.split("+")
    if hosts == ["all"]:
        hosts = app.config["PROXY"].keys()
    for host in hosts:
        ret, res = bird_command(host, proto, command)
        res = res.split("\n")

        if ret is False:
            errors.append("%s" % res)
            continue

        if len(res) <= 1:
            errors.append("%s: bird command failed with error, %s" % (host, "\n".join(res)))
            continue

        detail[host] = {"status": res[1], "description": add_links(res[2:])}

    return render_template('detail.html', detail=detail, command=command, errors=errors)


@app.route("/traceroute/<hosts>")
@app.route("/traceroute/<hosts>/<proto>")
def traceroute(hosts, proto="ipv4"):
    q = get_query()

    if not q:
        abort(400)

    set_session("traceroute", hosts, proto, q)

    if app.config.get("UNIFIED_DAEMON", False):
        if not ip_is_valid(q):
            try:
                if app.config.get("UNIFIED_TRACEROUTE_IPV6", True):
                    q = resolve_any(q)
                else:
                    q = resolve(q, "A")
            except:
                return error_page("%s is unresolvable" % q)
        if ipv6_is_valid(q):
            proto = "ipv6"
        else:
            proto = "ipv4"
    else:
        if proto == "ipv6" and not ipv6_is_valid(q):
            try:
                q = resolve(q, "AAAA")
            except:
                return error_page("%s is unresolvable or invalid for %s" % (q, proto))
        if proto == "ipv4" and not ipv4_is_valid(q):
            try:
                q = resolve(q, "A")
            except:
                return error_page("%s is unresolvable or invalid for %s" % (q, proto))

    errors = []
    infos = {}
    hosts = hosts.split("+")
    if hosts == ["all"]:
        hosts = app.config["PROXY"].keys()
    for host in hosts:
        status, resultat = bird_proxy(host, proto, "traceroute", q)
        if status is False:
            errors.append("%s" % resultat)
            continue


        infos[host] = add_links(resultat)
    return render_template('traceroute.html', infos=infos, errors=errors)


@app.route("/adv/<hosts>")
@app.route("/adv/<hosts>/<proto>")
def show_route_filter(hosts, proto="ipv4"):
    return show_route("adv", hosts, proto)


@app.route("/adv_bgpmap/<hosts>")
@app.route("/adv_bgpmap/<hosts>/<proto>")
def show_route_filter_bgpmap(hosts, proto="ipv4"):
    return show_route("adv_bgpmap", hosts, proto)


@app.route("/where/<hosts>")
@app.route("/where/<hosts>/<proto>")
def show_route_where(hosts, proto="ipv4"):
    return show_route("where", hosts, proto)


@app.route("/where_detail/<hosts>")
@app.route("/where_detail/<hosts>/<proto>")
def show_route_where_detail(hosts, proto="ipv4"):
    return show_route("where_detail", hosts, proto)


@app.route("/where_bgpmap/<hosts>")
@app.route("/where_bgpmap/<hosts>/<proto>")
def show_route_where_bgpmap(hosts, proto="ipv4"):
    return show_route("where_bgpmap", hosts, proto)


@app.route("/prefix/<hosts>")
@app.route("/prefix/<hosts>/<proto>")
def show_route_for(hosts, proto="ipv4"):
    return show_route("prefix", hosts, proto)


@app.route("/prefix_detail/<hosts>")
@app.route("/prefix_detail/<hosts>/<proto>")
def show_route_for_detail(hosts, proto="ipv4"):
    return show_route("prefix_detail", hosts, proto)


@app.route("/prefix_bgpmap/<hosts>")
@app.route("/prefix_bgpmap/<hosts>/<proto>")
def show_route_for_bgpmap(hosts, proto="ipv4"):
    return show_route("prefix_bgpmap", hosts, proto)


def get_as_name(_as):
    """return a string that contain the as number following by the as name

    It's the use whois database informations
    # Warning, the server can be blacklisted from ripe is too many requests are done
    """
    if not _as:
        return "AS?????"

    if not _as.isdigit():
        return _as.strip()

    name = mc.get(str('lg_%s' % _as))
    if not name:
        app.logger.info("asn for as %s not found in memcache", _as)
        asn_result = get_asn_from_as(_as)
        if asn_result:
            name = asn_result[-1].replace(" ","\r",1)
            mc.set(str("lg_%s" % _as), str(name), memcache_expiration)
        else:
            return "AS%s" % (_as)

    return "AS%s | %s" % (_as, name)


def get_as_number_from_protocol_name(host, proto, protocol):
    ret, res = bird_command(host, proto, "show protocols all %s" % protocol)
    re_asnumber = re.search("Neighbor AS:\s*(\d*)", res)
    if re_asnumber:
        return re_asnumber.group(1)
    else:
        return "?????"


@app.route("/bgpmap/")
def show_bgpmap():
    """return a bgp map in a png file, from the json tree in q argument"""

    data = get_query()
    if not data:
        abort(400)
        
    data = base64.b64decode(data)
    data = json.loads(data.decode('utf-8'))

    graph = pydot.Dot('BGPMAP', graph_type='digraph')

    nodes = {}
    edges = {}
    prepend_as = {}

    def escape(label):
        label = label.replace("&", "&amp;")
        label = label.replace(">", "&gt;")
        label = label.replace("<", "&lt;")
        return label

    def add_node(_as, **kwargs):
        if _as not in nodes:
            kwargs["label"] = '<<TABLE CELLBORDER="0" BORDER="0" CELLPADDING="0" CELLSPACING="0"><TR><TD ALIGN="CENTER">' + escape(kwargs.get("label", get_as_name(_as))).replace("\r","<BR/>") + "</TD></TR></TABLE>>"
            nodes[_as] = pydot.Node(_as, style="filled", fontsize="10", **kwargs)
            graph.add_node(nodes[_as])
        return nodes[_as]

    def add_edge(_previous_as, _as, **kwargs):
        kwargs["splines"] = "true"
        force = kwargs.get("force", False)

        edge_tuple = (_previous_as, _as)
        if force or edge_tuple not in edges:
            edge = pydot.Edge(*edge_tuple, **kwargs)
            graph.add_edge(edge)
            edges[edge_tuple] = edge
        elif "label" in kwargs and kwargs["label"]:
            e = edges[edge_tuple]

            label_without_star = kwargs["label"].replace("*", "")
            if e.get_label() is not None:
                labels = e.get_label().split("\r") 
            else:
                return edges[edge_tuple]
            if "%s*" % label_without_star not in labels:
                labels = [ kwargs["label"] ]  + [ l for l in labels if not l.startswith(label_without_star) ] 
                labels = sorted(labels, key=lambda x: x.endswith("*") and -1 or 1)
                
                label = escape("\r".join(labels))
                e.set_label(label)
        return edges[edge_tuple]

    for host, asmaps in data.items():
        add_node(host, label= "%s\r%s" % (host.upper(), app.config["DOMAIN"].upper()), shape="box", fillcolor="#F5A9A9")

        as_number = app.config["AS_NUMBER"].get(host, None)
        if as_number:
            node = add_node(as_number, fillcolor="#F5A9A9")
            edge = add_edge(as_number, nodes[host])
            edge.set_color("red")
            edge.set_style("bold")
    
    #colors = [ "#009e23", "#1a6ec1" , "#d05701", "#6f879f", "#939a0e", "#0e9a93", "#9a0e85", "#56d8e1" ]
    previous_as = None
    hosts = list(data.keys())
    for host, asmaps in data.items():
        first = True
        for asmap in asmaps:
            previous_as = host
            color = "#%x" % random.randint(0, 16777215)

            hop = False
            hop_label = ""
            for _as in asmap:
                if _as == previous_as:
                    if not prepend_as.get(_as, None):
                        prepend_as[_as] = {}
                    if not prepend_as[_as].get(host, None):
                        prepend_as[_as][host] = {}
                    if not prepend_as[_as][host].get(asmap[0], None):
                        prepend_as[_as][host][asmap[0]] = 1
                    prepend_as[_as][host][asmap[0]] += 1
                    continue

                if not hop:
                    hop = True
                    if _as not in hosts:
                        hop_label = _as 
                        if first:
                            hop_label = hop_label + "*"
                        continue
                    else:
                        hop_label = ""

                
                add_node(_as, fillcolor=("white"))
                if first:
                    nodes[_as].set_fillcolor("#F5A9A9")
                if hop_label:
                    edge = add_edge(nodes[previous_as], nodes[_as], label=hop_label, fontsize="7")
                else:
                    edge = add_edge(nodes[previous_as], nodes[_as], fontsize="7")

                hop_label = ""

                if first:
                    edge.set_style("bold")
                    edge.set_color("red")
                elif edge.get_color() != "red":
                    edge.set_style("dashed")
                    edge.set_color(color)

                previous_as = _as
            first = False

    if previous_as:
        node = add_node(previous_as)
        node.set_shape("box")

    for _as in prepend_as:
       for n in set([ n for h, d in prepend_as[_as].items() for p, n in d.items() ]):
           graph.add_edge(pydot.Edge(*(_as, _as), label=" %dx" % n, color="grey", fontcolor="grey"))
        

    fmt = request.args.get('fmt', 'png')
    #response = Response("<pre>" + graph.create_dot() + "</pre>")
    if fmt == "png":
        response = Response(graph.create_png(), mimetype='image/png')
    elif fmt == "svg":
        response = Response(graph.create_svg(), mimetype='image/svg+xml')
    else:
        abort(400, "Incorrect format")
    response.headers['Last-Modified'] = datetime.now()
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response



def build_as_tree_from_raw_bird_ouput(host, proto, text):
    """Extract the as path from the raw bird "show route all" command"""

    path = None
    paths = []
    net_dest = None
    for line in text:
        line = line.strip()

        # check for bird2 style line containing protocol name
        # matches: ... unicast_[(protocol)_ ...
        b2_unicast_line = re.search(r'(.*)unicast\s+\[(\w+)\s+', line)
        if b2_unicast_line:
            # save the net_dest and protocol name for later
            if b2_unicast_line.group(1).strip():
                net_dest = b2_unicast_line.group(1).strip()
            peer_protocol_name = b2_unicast_line.group(2).strip()

        peer_match = False

        # check line for bird1 style line
        # matches: ___via_(next hop ip addr)_on_(iface)_[(protocol)_ ...
        b1_peer_line = re.search(r'(.*)via\s+([0-9a-fA-F:\.]+)\s+on.*\[(\w+)\s+', line)
        if b1_peer_line:
            # save the net_dest, peer and protocol name for later
            if b1_peer_line.group(1).strip():
                net_dest = b1_peer_line.group(1).strip()
            peer_ip = b1_peer_line.group(2).strip()
            peer_protocol_name = b1_peer_line.group(3).strip()
            # flag that a match was found
            peer_match = True

        else:
            # if this wasn't a bird1 style peer line, then check for a bird2
            # style line instead. Doing the check in the else clause prevents
            # falsely matching bird1 lines
            # matches: _via_(next hop address)
            b2_peer_line = re.search(r'via\s+([0-9a-fA-F:\.]+)', line)
            if b2_peer_line:
                peer_ip = b2_peer_line.group(1).strip()
                # flag that a match was found
                peer_match = True

        if peer_match:
            # common code for when either a bird1 or bird2 peer line was found
            if path:
                path.append(net_dest)
                paths.append(path)
                path = None

            # Check if via line is a internal route
            for rt_host, rt_ips in app.config["ROUTER_IP"].items():
                # Special case for internal routing
                if peer_ip in rt_ips:
                    paths.append([peer_protocol_name, rt_host])
                    path = None
                    break
                else:
                    path = [ peer_protocol_name ]

        # check for unreachable routes (common for bird1 & 2)
        # matches: ...unreachable_[(protocol)_
        unreachable_line = re.search(r'(.*)unreachable\s+\[(\w+)\s+', line)
        if unreachable_line:
            if path:
                path.append(net_dest)
                paths.append(path)
                path = None

            if unreachable_line.group(1).strip():
                net_dest = unreachable_line.group(1).strip()

        # check for on-link routes
        onlink_line = re.search(r'^dev', line)
        if onlink_line:
            paths.append([peer_protocol_name, net_dest])
            path = None

        if line.startswith("BGP.as_path:") and path:
            ASes = line.replace("BGP.as_path:", "").strip().split(" ")
            if path:
                path.extend(ASes)
            else:
                path = ASes
    
    if path:
        path.append(net_dest)
        paths.append(path)

    return paths


def show_route(request_type, hosts, proto):
    expression = get_query()
    if not expression:
        abort(400)

    set_session(request_type, hosts, proto, expression)

    bgpmap = request_type.endswith("bgpmap")

    all = (request_type.endswith("detail") and " all" or "")
    if bgpmap:
        all = " all"

    if request_type.startswith("adv"):
        command = "show route " + expression.strip()
        if bgpmap and not command.endswith("all"):
            command = command + " all"
    elif request_type.startswith("where"):
        command = "show route where net ~ [ " + expression + " ]" + all
    else:
        mask = ""
        if len(expression.split("/")) == 2:
            expression, mask = (expression.split("/"))

        if app.config.get("UNIFIED_DAEMON", False):
            if not ip_is_valid(expression):
                try:
                    expression = resolve_any(expression)
                except:
                    return error_page("%s is unresolvable" % expression)

            if not mask and ipv4_is_valid(expression):
                mask = "32"
            if not mask and ipv6_is_valid(expression):
                mask = "128"
            if not mask_is_valid(mask):
                return error_page("mask %s is invalid" % mask)
        else:
            if not mask and proto == "ipv4":
                mask = "32"
            if not mask and proto == "ipv6":
                mask = "128"
            if not mask_is_valid(mask):
                return error_page("mask %s is invalid" % mask)

            if proto == "ipv6" and not ipv6_is_valid(expression):
                try:
                    expression = resolve(expression, "AAAA")
                except:
                    return error_page("%s is unresolvable or invalid for %s" % (expression, proto))
            if proto == "ipv4" and not ipv4_is_valid(expression):
                try:
                    expression = resolve(expression, "A")
                except:
                    return error_page("%s is unresolvable or invalid for %s" % (expression, proto))

        if mask:
            expression += "/" + mask

        command = "show route for " + expression + all

    detail = {}
    errors = []
    hosts = hosts.split("+")
    if hosts == ["all"]:
        hosts = list(app.config["PROXY"].keys())
    allhosts = hosts[:]
    for host in allhosts:
        ret, res = bird_command(host, proto, command)
        res = res.split("\n")

        if ret is False:
            errors.append("%s" % res)
            continue

        if len(res) <= 1:
            errors.append("%s: bird command failed with error, %s" % (host, "\n".join(res)))
            continue

        if bgpmap:
            detail[host] = build_as_tree_from_raw_bird_ouput(host, proto, res)
            #for internal routes via hosts not selected
            #add them to the list, but only show preferred route
            if host not in hosts:
                detail[host] = detail[host][:1]
            for path in detail[host]:
                if len(path) == 2:
                    if (path[1] not in allhosts) and (path[1] in app.config["PROXY"]):
                        allhosts.append(path[1])

        else:
            detail[host] = add_links(res)

    if bgpmap:
        # in python3 b64encode() encodes a byte-like object in to bytes
        # so the json string needs to be encoded to bytes and then the
        # base64 result decoded back to a string again
        detail = json.dumps(detail)
        detail = base64.b64encode(detail.encode('utf-8'))
        detail = detail.decode('utf-8')

    return render_template((bgpmap and 'bgpmap.html' or 'route.html'), detail=detail, command=command, expression=expression, errors=errors)


if __name__ == "__main__":
    app.run(app.config.get("BIND_IP", "0.0.0.0"), app.config.get("BIND_PORT", 5000))
