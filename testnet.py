#!/usr/bin/env python3
import subprocess
import logging
import sys
import os
import signal
import json
import argparse
import shutil
import time
import getpass
import hashlib
import struct
import base64

if sys.version_info.major < 3:
    print("Python 2 is not supported, use python3")
    sys.exit(1)

from contextlib import suppress

def fatal_error(msg):
    """Show an error and exit"""
    logging.error(msg)
    sys.exit(1)

def load_config(path):
    if not os.path.exists(path) or not os.access(path, os.R_OK):
        fatal_error("Can't read {}".format(path))

    try:
        with open(path, "r") as f: c = f.read()
        config = json.loads(c)
    except:
        fatal_error("Error parsing config file")

    for v in ["i2p_install_path", "i2pd_binary"]:
        if v in config and not os.path.exists(config[v]):
            fatal_error("'{}' doesn't exist".format(config[v]))

    return config

def run(command):
    """Execute a command in the shell, return the exit code"""
    logging.debug(command)
    res = subprocess.run(command, shell=True, stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE)
    return res.returncode

def ns_run(namespace, command):
    """Execute a command in the network namespace as root"""
    return run("sudo -n ip netns exec {} {}".format(namespace, command))

def ns_run_as_user(namespace, command):
    """Execute a command in the network namespace as a current user"""
    return run("sudo -n ip netns exec {} su -c '{}' {}".format(
                          namespace, command, getpass.getuser()))

def ri_b64hash(path):
    """Get Base64 encoded hash of a router from a RouterInfo file"""
    with open(path, "rb") as f: data = f.read()
    cert_len = struct.unpack("!H", data[385:387])[0]
    public_data = data[:387+cert_len]
    return base64.b64encode(hashlib.sha256(public_data).digest(), 
                            altchars=b"-~").decode()

def is_ready(path):
    """Check if router.info file is ready for use in a reseed"""
    ready = False
    if os.path.exists(path):
        with open(path, "rb") as f: data = f.read()
        ssu_ready  = b"\x63\x61\x70\x73\x3d\x02\x42\x43\x3b"
        ntcp_ready = b"\x63\x61\x70\x73\x3d\x03\x50\x66\x52\x3b"
        ready = ssu_ready in data or ntcp_ready in data
    return ready

def create_gateway_namespace(namespace):
    """Setup gateway network namespace"""
    run("sudo -n ip netns add {}".format(namespace))
    ns_run(namespace, "ip link set dev lo up")
    ns_run(namespace, "sysctl net.ipv4.conf.all.forwarding=1")

def add_network_bridge_to_gateway(gateway_ns, network, network_gateway_address):
    """Add bridge interface for the network"""
    ns_run(gateway_ns, "ip link add name br{} type bridge".format(network))
    ns_run(gateway_ns, "ip link set br{} up".format(network))
    ns_run(gateway_ns, "ip address add {} dev br{}".format(
        network_gateway_address, network))

def create_router_namespace(name, ip, network_name, network, gateway):
    """Setup I2P router network namespace"""
    run("sudo -n ip netns add {}".format(name))
    run("sudo -n ip link add eth0 netns {} type veth peer netns {} name veth-{}".format(
        name, gateway, name))
    ns_run(name, "ip link set dev lo up")
    ns_run(name, "ip link set dev eth0 up".format(name))
    ns_run(name, "ip address add {} dev eth0".format(ip))
    ns_run(gateway, "ip link set veth-{} up".format(name))
    ns_run(gateway, "ip link set veth-{} master br{}".format(name, network_name))
    ns_run(name, "ip route add {} dev eth0 proto kernel scope link src {}".format(
        network["subnet"], ip))
    ns_run(name, "ip route add default via {} dev eth0".format(
        network["gateway"].split("/")[0]))

def start_i2p(namespace, i2p_install_path, datadir):
    """Prepare datadir and start I2P router in its own network namespace"""
    for t in ["certificates", "docs", "eepget", "eepsite", "geoip", 
              "history.txt", "hosts.txt", "lib", "locale", "webapps"]:
        os.symlink(os.path.join(i2p_install_path, t), os.path.join(datadir, t))

    for t in ["i2psvc", "libwrapper.so"]:
        os.symlink(os.path.join(i2p_install_path, "lib/wrapper/linux64", t), 
                   os.path.join(datadir, t))

    with open(os.path.join(datadir, "wrapper.config"), "w") as wt:
        with open(os.path.join(i2p_install_path, "wrapper.config"), "r") as ws:
            for l in ws.readlines():
                if not l.startswith("#"):
                    wt.write(l.replace("$INSTALL_PATH", datadir))

            extra_config = {"3": "i2p.dir.pid=logs", "4": "i2p.dir.temp=tmp",
                "5": "i2p.dir.config={}".format(datadir),
                "6": "router.pingFile={}/router.ping".format(datadir)}

            for k, v in extra_config.items():
                wt.write("wrapper.java.additional.{}=-D{}\n".format(k, v))
                wt.write("wrapper.java.additional.{}.stripquotes=TRUE\n".format(k))

    with open(os.path.join(datadir, "i2prouter"), "w") as wt:
        with open(os.path.join(i2p_install_path, "i2prouter"), "r") as ws:
            for l in ws.readlines():
                if not l.startswith("#"):
                    if l.startswith("I2PTEMP="):
                        wt.write("I2P={}\nI2P_CONFIG_DIR={}\n".format(
                            datadir, datadir))
                    else:
                        wt.write(l)

    command = "/bin/sh {} start".format(os.path.join(datadir, "i2prouter"))
    ns_run_as_user(namespace, command)

def stop_i2p(datadir):
    command = "/bin/sh {} stop".format(os.path.join(datadir, "i2prouter"))
    run(command)

def start_i2pd(namespace, binary, args, datadir):
    args += ["--datadir", datadir, "--daemon", "--reseed.threshold", "0"]
    command = "{} {}".format(binary, " ".join(args))
    ns_run_as_user(namespace, command)

def stop_i2pd(datadir):
    pidfile = os.path.join(datadir, "i2pd.pid")
    if os.path.exists(pidfile):
        with open(pidfile) as f:
            with suppress(ProcessLookupError):
                pid = int(f.read().strip())
                os.kill(pid, signal.SIGKILL)

def start_router(config, node):
    """Prepare environment for a router based on it's configuration and start it"""
    create_router_namespace(node["name"], node["ip"], node["network"], 
                            config["networks"][node["network"]], config["gateway"])

    datadir = os.path.abspath(os.path.join(config["workspace"], node["name"]))
    if not os.path.exists(datadir): 
        os.mkdir(datadir)
        if os.path.exists(os.path.join(config["workspace"], "netDb")):
            shutil.copytree(os.path.join(config["workspace"], "netDb"), 
                            os.path.join(datadir, "netDb"))

    if node["router"] == "i2pd":
        binary = node["i2pd_binary"] if "i2pd_binary" in node else config["i2pd_binary"]
        args = []
        args += node["i2pd_args"] if "i2pd_args" in node else config["i2pd_args"]
        if "custom_args" in node: args += node["custom_args"]
        if "floodfill" in node and node["floodfill"] == True:
            args += ["--floodfill"]
        if config["debug_logging"]: args += ["--loglevel", "debug"]

        start_i2pd(node["name"], binary, args, datadir)
    else:
        ip = node["ip"].split("/")[0]
        options = node["i2p_options"] if "i2p_options" in node else config["i2p_options"]
        if "custom_options" in node: options += node["custom_options"]
        options.extend(["i2np.allowLocal=true",
                        "i2np.udp.bindInterface={}".format(ip),
                        "i2np.ntcp.bindInterface={}".format(ip)])
        if "floodfill" in node and node["floodfill"] == True:
            options.append("router.floodfillParticipant=true")

        with open(os.path.join(datadir, "router.config"), "w") as f:
            for o in options: f.write("{}\n".format(o))

        if config["debug_logging"]:
            with open(os.path.join(datadir, "logger.config"), "w") as f:
                f.write("logger.defaultLevel=DEBUG")

        with open(os.path.join(datadir, "clients.config"), "w") as f:
            clients = node["clients_config"] if "clients_config" in node else config["clients_config"]
            for c in clients: f.write("{}\n".format(c))

        start_i2p(node["name"], config["i2p_install_path"], datadir)

def stop_router(config, node):
    datadir = os.path.abspath(os.path.join(config["workspace"], node["name"]))
    if node["router"] == "i2pd":
        stop_i2pd(datadir)
    else:
        stop_i2p(datadir)

    run("sudo -n ip netns del {}".format(node["name"]))

def count_routerinfos(netdb):
    """Count router info files in the netDb directory"""
    i = 0
    if os.path.exists(netdb):
        for d in os.walk(netdb): i += len(d[2])
    return i

def router_status(config, node):
    state = "down"
    info = "not running"

    datadir = os.path.abspath(os.path.join(config["workspace"], node["name"]))
    if os.path.exists(datadir):
        if node["router"] == "i2pd":
            pidfile = os.path.join(datadir, "i2pd.pid")
            logfile = os.path.join(datadir, "i2pd.log")
        else:
            pidfile = os.path.join(datadir, "i2p.pid")
            logfile = os.path.join(datadir, "logs", "log-router-0.txt")

        if os.path.exists(pidfile):
            with open(pidfile, "r") as f: pid = f.read().strip() 
            if os.path.exists("/proc/{}".format(pid)): state = "up"
            info = "Known Routers: {}\nIP: {} Network: {}\nPID: {}".format(
                        count_routerinfos(os.path.join(datadir, "netDb")),
                        node["ip"], node["network"], pid)

        info += "\nDatadir: {} Log: {}".format(datadir, logfile)
    return """{} is {}\n{}\n""".format(node["name"], state, info)

def make_netdb_dir(conf, reseed_nodes):
    """Create reseed netDb dir and populate it with router.info's from reseed nodes"""
    netdb_dir = os.path.abspath(os.path.join(conf["workspace"], "netDb"))
    os.mkdir(netdb_dir)

    for n in reseed_nodes:
        ri_path = os.path.join(conf["workspace"], n["name"], "router.info")
        for x in range(1200): # two minutes max
            if is_ready(ri_path):
                ri_hash = ri_b64hash(ri_path)
                t_dir = os.path.join(netdb_dir, "r{}".format(ri_hash[0]))
                if not os.path.exists(t_dir): os.mkdir(t_dir)
                shutil.copy(ri_path, os.path.join(t_dir, 
                                "routerInfo-{}.dat".format(ri_hash)))
                break
            else:
                time.sleep(0.1)

### tool actions

def start(args):
    conf = load_config(args.config)
    if not os.path.exists(conf["workspace"]): os.mkdir(conf["workspace"])

    create_gateway_namespace(conf["gateway"])
    for n in conf["networks"].keys():
        add_network_bridge_to_gateway(conf["gateway"], n, 
                                      conf["networks"][n]["gateway"])

    reseed_nodes = [n for n in conf["nodes"] if "reseed" in n and n["reseed"] == True]

    for n in reseed_nodes: start_router(conf, n)

    make_netdb_dir(conf, reseed_nodes)

    for n in conf["nodes"]: 
        if n not in reseed_nodes: start_router(conf, n)

def stop(args):
    conf = load_config(args.config)

    for n in conf["nodes"]:
        stop_router(conf, n)
        with suppress(FileNotFoundError):
            shutil.rmtree(os.path.join(conf["workspace"], n["name"]))

    run("sudo -n ip netns del {}".format(conf["gateway"]))

    with suppress(FileNotFoundError):
        shutil.rmtree(os.path.join(conf["workspace"], "netDb"))

def status(args):
    conf = load_config(args.config)
    print("Network: ")
    for net in conf["networks"].keys():
        num = len([n for n in conf["nodes"] if n["network"] == net])
        print("{}: {} has {} nodes".format(net, conf["networks"][net]["subnet"], num))
    print("\nRouters:")
    for n in conf["nodes"]:
        print(router_status(conf, n))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', '-d', action="store_true",
            help="Debug output")

    subparsers = parser.add_subparsers(title="actions", 
            help="Command to execute")

    start_parser = subparsers.add_parser(
        "start", description="starts a testnet", usage="%(prog)s config.json")
    start_parser.add_argument('config', metavar="CONFIG", help="Config file")
    start_parser.set_defaults(func=start)

    stop_parser = subparsers.add_parser(
        "stop", description="stops a testnet", usage="%(prog)s config.json")
    stop_parser.add_argument('config', metavar="CONFIG", help="Config file")
    stop_parser.set_defaults(func=stop)

    status_parser = subparsers.add_parser(
        "status", description="print testnet status", usage="%(prog)s config.json")
    status_parser.add_argument('config', metavar="CONFIG", help="Config file")
    status_parser.set_defaults(func=status)

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    if not sys.platform.startswith("linux"):
        fatal_error("This script only runs on Linux, your OS is not supported")

    if os.getuid() == 0:
        fatal_error("You MUST run this script as a non-root user")

    if not os.path.exists("/usr/bin/sudo"):
        fatal_error("/usr/bin/sudo is missing, please install 'sudo' package")

    res = subprocess.run("sudo -n -l", shell=True, stderr=subprocess.DEVNULL, 
                         stdout=subprocess.DEVNULL)
    if res.returncode != 0:
        fatal_error("sudo is not configured correctly, read the manual")

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
