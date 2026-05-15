import getpass

from url_threat_checker.auth import hash_password


def main() -> None:
    password = getpass.getpass("Password to hash: ")
    print(hash_password(password))


if __name__ == "__main__":
    main()
