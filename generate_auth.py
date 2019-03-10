import qrcode
import pyotp
import os
from argparse import ArgumentParser


def generate_qrcode(host, secret):
    """
    Generates QRCode image. Saves in the fashion <hostname>.png
    """
    if host is None:
        host = "hostname"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4)

    data = "otpauth://totp/knocker@{0}?secret={1}".format(host, secret)

    qr.add_data(data)
    qr.make(fit=True)
    print("[+] Generating QRCode...")
    img = qr.make_image(fill_color="black", back_color="white")
    print("[+] Done! QRCode image saved to {0}.png".format(host))
    img.save("{0}.png".format(host), "PNG")


def generate_code(outfile="secret.code", host=None):
    """
    Generates Random Base32 secret and calls generate_code() function to
    generate a Google Authenticator App scanable QRCode image.
    Additionally, it also saves a "secret.code" file containing the
    base32 secret.
    """
    print("[+] Generating Random Secret...")
    secret = pyotp.random_base32()
    if host is None:
        host = os.uname()[1]
    generate_qrcode(host, secret)

    print("[+] Saving secret to file {0}".format(outfile))
    with open(outfile, "w+") as f:
        f.write(secret)
        print("[+] Done!")


if __name__ == "__main__":
    parser = ArgumentParser(
        description="\
        Utility to generate QRCode Image and a random base32 \
        secret that will be used by the knocker program and can also be \
        scanned by the Google Authenticator App.")
    parser.add_argument(
        "-qr",
        "--only-qr",
        action="store_true",
        help="Specify to only generate QRCode Image. Requires --secret.")
    parser.add_argument(
        "-H",
        "--hostname",
        default=None,
        type=str,
        help="Hostname of the machine.")
    parser.add_argument(
        "-s",
        "--secret",
        default=None,
        type=str,
        help="Specified secret to use for creating QRCode Image.")
    parser.add_argument(
        "-o",
        "--outfile",
        default="secret.code",
        type=str,
        help="Name of file where the generated SECRET will be stored.\
         Default is 'secret.code'")

    args = parser.parse_args()

    if args.only_qr:
        if args.secret is None:
            print("[!] No SECRET specified. Exiting...")
            exit()
        else:
            generate_qrcode(host=args.hostname, secret=args.secret)
    else:
        answer = str(input("Generate Code [Y/n]?"))
        if answer is "Y" or answer is "y":
            generate_code(outfile=args.outfile, host=args.hostname)
        else:
            print("[!] Exiting...")
            exit()

