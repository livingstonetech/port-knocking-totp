#!/usr/bin/env python3
import pyotp
import sys
import time
import subprocess


conf_iptables = """
[options]
    logfile = /var/log/knockd.log
    Interface = ens160

[TOTP]
    sequence = {0},{1}
    tcpflags = syn
    seq_timeout = 5
    start_command = /sbin/iptables -F;/sbin/iptables -A INPUT -p tcp --dport {2} -j ACCEPT
    cmd_timeout = 22
    stop_command = /sbin/iptables -D INPUT -p tcp --dport {2} -j ACCEPT; /sbin/iptables -A INPUT -p tcp --dport {2} -j REJECT
"""


def get_four_digit(knock):
    while True:
        if knock >= 1000:
            return knock
        else:
            knock = knock * 10


def get_knocks(code):
    first_knock = get_four_digit(int(code / 100))
    second_knock = get_four_digit(int(code % 10000))
    return first_knock, second_knock


def write_to_knockd_conf(first_knock, second_knock, port, mode):
    if mode == "iptables":
        global conf_iptables
        conf_iptables_formatted = conf_iptables.format(
            str(first_knock),
            str(second_knock),
            str(port))
        with open("/etc/knockd.conf", "w+") as cnf:
            cnf.write(conf_iptables_formatted)

    subprocess.run(["systemctl", "restart", "knockd"])


def populate_config(config, knockd_conf):
    """
    Takes input a dictionary of the parsed config.json and knockd_conf
    skeleton and replaces the values in the skeleton file with the config
    values.
    """
    knockd_conf = knockd_conf.format(
        log_file=config['log_file'],
        interface=config['interface'],
        timeout=config['timeout'],
        port=config['port'],
        knock_1=config['knock_1'],
        knock_2=config['knock_2'])
    return knockd_conf


if __name__ == "__main__":
    """
        Three arguments: ./knocker.py [OAUTH_SECRET] [PORT] [MODE]
    """
    if len(sys.argv) < 4:
        print("Oh, I am going to need a little more than that.")
        print("USAGE: ./knocker.py [OAUTH_SECRET] [PORT] [MODE]")
        exit()
    AUTH = sys.argv[1]
    CODE = pyotp.TOTP(AUTH)
    port = sys.argv[2]
    mode = sys.argv[3]

    # Initial Run.
    OTP = CODE.now()
    knock1, knock2 = get_knocks(int(OTP))
    print("Knocks: \t%d\t%d" % (knock1, knock2))
    write_to_knockd_conf(knock1, knock2, port, mode)
    last_otp = OTP

    while True:
        try:
            epoch = int(time.time() % 30)
            if epoch == 0:
                OTP = CODE.now()
                if OTP == last_otp:
                    continue
                knock1, knock2 = get_knocks(int(OTP))
                print("Knocks:\t%d\t%d" % (knock1, knock2))
                write_to_knockd_conf(knock1, knock2, port, mode)
                last_otp = OTP
        except KeyboardInterrupt:
            print("Exiting...")
            break

        except Exception as e:
            print("ERROR: %s" % str(e))
