from cryptography.fernet import Fernet
from pathlib import Path


class Vault:
    def __init__(self):
        self.key = None
        self.passwords_file = None
        self.passwords_dict = {}

    def create_key(self, path, overwrite=False):
        if Path(path).exists() and overwrite == False:
            raise FileExistsError(
                "'master.key' exists. Please pass overwrite = True argument"
            )

        self.key = Fernet.generate_key()

        with open(path, "wb") as f:
            f.write(self.key)

    def load_key(self, path):
        if not Path(path).exists():
            raise FileNotFoundError(
                "'master.key' file not found. Create using .generate_key()"
            )

        with open(path, "rb") as f:
            self.key = f.read()

    def create_database(self, path, initial_values=None):
        self.passwords_file = path

        if initial_values:
            for key, value in initial_values.items():
                self.add_password(key, value)

    def load_passwords(self, path):
        self.passwords_file = path

        with open(path, "r") as f:
            for line in f:
                site, encrypted = line.split(":")
                self.passwords_dict[site] = (
                    Fernet(self.key).decrypt(encrypted.encode()).decode()
                )

    def add_password(self, site, password):
        if self.passwords_file:
            encrypted = Fernet(self.key).encrypt(password.encode())
            with open(self.passwords_file, "a+") as f:
                f.write(site + ":" + encrypted.decode() + "\n")

    def get_password(self, site):
        return self.passwords_dict[site]


def main():
    vault = Vault()

    # vault.create_key(True)
    vault.load_key("master.key")
    # print(vault.key)
    testpwds = {"email": "password123", "github": "testingtesting"}
    vault.create_database("./pass", testpwds)
    vault.load_passwords("./pass")

    print(vault.get_password("email"))


if __name__ == "__main__":
    main()
