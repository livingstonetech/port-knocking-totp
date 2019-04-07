#!/usr/bin/env python3
from argparse import ArgumentParser
from configparser import ConfigParser
import pyotp
import time
import subprocess
import platform
import os
import shutil


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


def check_sanity(config_path):
    """
    Function to check if the program won't crash when it is run.
    Following are the parameters that are checked for:
        - Checks if NOT Windows
        - Checks if root
        - Checks if knockd service exists
        - Checks if iptables exists
        - Checks if specified config file exists and is accessible
        - Checks if config file is valid (Syntax)
        - Checks if the "totp_secret" option of the config file is filled
    """
    os_name = platform.system()
    print("[+] Detecting operating system...")
    if os_name == "Windows":
        win_32 = platform.win32_ver()
        print("----> [!] Detected Windows: {} {} {}".format(win_32[0],
                                                            win_32[1],
                                                            win_32[2]))
        print("----> [!] We do not support Windows (yet).")
        print("----> [!] Exiting...")
        exit()
    else:
        print("----> [+] Detected OS: {}".format(os_name))
        print("[+] Checking for root privileges...")
        if os.geteuid() != 0:
            print("----> [!] Please run this file as root")
            print("----> [!] Exiting...")
            exit()
        print("[+] Checking if 'knockd' exists...")
        if shutil.which("knockd") is None:
            print("----> [!] Knockd is not installed or not found")
            print("----> [!] Please install and then run")
            print("----> [!] Exiting...")
            exit()
        print("[+] Checking if iptables exists...")
        if shutil.which("iptables") is None:
            print("----> [!] iptables was not detected")
            print("----> [!] Exiting...")
            exit()
        print("[+] Checking config file")
        try:
            config_file = open(config_path, "r")
            print("----> [+] Found file: {}".format(config_path))
            config_file.close()
        except Exception as e:
            print("----> [!] Something unforseen happened.")
            print("----> [!] Exception: {}".format(e))
            print("----> [!] Exiting...")
            exit()
        print("[+] Checking config file")
        try:
            config_args = ConfigParser()
            config_args.read(config_path)
            print("----> [+] Successfully parsed config file")
            print("[+] Checking parsed values for empty entries")
            for section in config_args.sections():
                print("[+] Checking section: {}".format(section))
                sec = config_args[section]
                for key in list(config_args[section]):
                    print("--------> [+] Checking {}".format(key))
                    if sec[key] == "":
                        print("------------> [!] Empty!")
                        print("------------> [!] Please fill: {}".format(key))
                        exit()
            print("[+] Checking secret...")
            if len(config_args['KNOCKER']['totp_secret']) != 16:
                print("----> [!] Secret does not seem right! Please check it.")
                print("----> [!] Run generate_auth.py to create a new secret")
                print("----> [!] Exiting...")
                exit()
            else:
                print("----> [+] Secret looks valid.")
        except Exception as e:
            print("----> [!] Something unforseen happened.")
            print("----> [!] Exception: {}".format(e))
            print("----> [!] Exiting...")
            exit()

    print("[+] All systems go!")


def write_to_knockd_conf(first_knock, second_knock, port, config, cf_template):
    knocker_config = config["KNOCKER"]
    knockd_config = config["KNOCKD"]
    cf_formatted = cf_template.format(
        log_file=knockd_config["knockd_log_file"],
        interface=knocker_config["interface"],
        knock_1=first_knock,
        knock_2=second_knock,
        port=port,
        timeout=knocker_config["timeout"])
    with open(knockd_config["knockd_config_file"], "w+") as k_cnf:
        k_cnf.write(cf_formatted)
        print("----> [+] Written new config to: {}".format(
            knockd_config["knockd_config_file"]))

    print("----> [+] Restarting service...")
    subprocess.run(["systemctl", "restart", "knockd"])
    print("----> [+] Done!\n")


if __name__ == "__main__":
    """
        Entry point
    """
    PARSER = ArgumentParser(
        description="Port knocking utility that leverages knockd and iptables")
    PARSER.add_argument(
        "-c",
        "--config",
        type=str,
        required=True,
        help="Path to Knocker config file.")
    PARSER.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Skip checking of permissions and binaries")

    ARGS = PARSER.parse_args()
    if not ARGS.force:
        check_sanity(ARGS.config)
    else:
        print("[!] Skipping sanity check. NOT SAFE.")

    CONF_ARGS = ConfigParser()
    CONF_ARGS.read(ARGS.config)
    AUTH = CONF_ARGS['KNOCKER']['totp_secret']
    PORT = CONF_ARGS['KNOCKER']['port']
    CF_TEMPLATE = open(CONF_ARGS["KNOCKD"]["knockd_config_file_template"], "r")
    CF_TEMPLATE = CF_TEMPLATE.read()
    CODE = pyotp.TOTP(AUTH)
    print("[+] Starting knockd...")
    # Initial Run.
    OTP = CODE.now()
    knock1, knock2 = get_knocks(int(OTP))
    write_to_knockd_conf(knock1, knock2, PORT, CONF_ARGS, CF_TEMPLATE)
    last_otp = OTP

    while True:
        try:
            epoch = int(time.time() % 30)
            if epoch == 0:
                OTP = CODE.now()
                if OTP == last_otp:
                    continue
                knock1, knock2 = get_knocks(int(OTP))
                print("[+] Knocks:\t%d\t%d" % (knock1, knock2))
                write_to_knockd_conf(knock1,
                                     knock2,
                                     PORT,
                                     CONF_ARGS,
                                     CF_TEMPLATE)
                last_otp = OTP
        except KeyboardInterrupt:
            print("[!] Exiting...")
            break

        except Exception as e:
            print("[!] Something unforseen happened.")
            print("[!] Exception: {}".format(e))
