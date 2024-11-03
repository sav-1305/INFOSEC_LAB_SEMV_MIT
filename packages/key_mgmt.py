import csv
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from phe import paillier  # Import for Paillier encryption scheme

class KeyDistributionCentre:
    FILE_PATH = "keys.csv"

    def __init__(self, key_generator, key_type):
        """
        Initializes the Key Distribution Centre with a key generation function.

        :param key_generator: A function that generates a private and public key pair.
        :param key_type: The type of key (e.g., "RSA", "ECC", "Paillier").
        """
        self.keys = {}
        self.key_generator = key_generator
        self.key_type = key_type
        self.load_keys_from_csv()

    def load_keys_from_csv(self):
        """
        Loads existing keys from a CSV file.
        """
        try:
            with open(self.FILE_PATH, mode="r", newline="") as file:
                reader = csv.reader(file)
                for row in reader:
                    name, key_type, private_key_data, public_key_data = row

                    if key_type == "RSA":
                        private_key = serialization.load_pem_private_key(
                            private_key_data.encode(),
                            password=None,
                            backend=default_backend()
                        )
                        public_key = serialization.load_pem_public_key(
                            public_key_data.encode(),
                            backend=default_backend()
                        )

                    elif key_type == "ECC":
                        private_key = serialization.load_pem_private_key(
                            private_key_data.encode(),
                            password=None,
                            backend=default_backend()
                        )
                        public_key = serialization.load_pem_public_key(
                            public_key_data.encode(),
                            backend=default_backend()
                        )

                    elif key_type == "Paillier":
                        private_key = tuple(map(int, private_key_data.split(",")))
                        public_key = tuple(map(int, public_key_data.split(",")))

                    self.keys[name] = {
                        'key_type': key_type,
                        'private_key': private_key,
                        'public_key': public_key
                    }
        except FileNotFoundError:
            open(self.FILE_PATH, 'w').close()

    def save_key_to_csv(self, name, public_key, private_key):
        """
        Saves a single key pair to the CSV file.

        :param name: The identifier for the key pair.
        :param private_key: The private key to store.
        :param public_key: The public key to store.
        """
        if self.key_type == "RSA" or self.key_type == "ECC":
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()

            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            private_key_data = private_key_pem
            public_key_data = public_key_pem

        elif self.key_type == "Paillier":
            public_key_data = f"{public_key[0]},{public_key[1]}"
            private_key_data = f"{private_key[0]},{private_key[1]}"

        with open(self.FILE_PATH, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([name, self.key_type, private_key_data, public_key_data])

    def generate_key_pair(self):
        """
        Uses the provided key generation function to create a private and public key pair.

        :return: Tuple of (public_key, private_key)
        """
        return self.key_generator()

    def store_key(self, name, public_key, private_key):
        """
        Stores the private and public key for a given name in memory and appends them to the CSV file.

        :param name: The identifier for the key pair.
        :param private_key: The private key to store.
        :param public_key: The public key to store.
        """
        self.keys[name] = {
            'key_type': self.key_type,
            'private_key': private_key,
            'public_key': public_key
        }
        self.save_key_to_csv(name, public_key, private_key)

    def get_public_key(self, name):
        """
        Retrieves the public key associated with a given name.

        :param name: The identifier for the key pair.
        :return: The public key.
        """
        return self.keys[name]['public_key']

    def get_private_key(self, name):
        """
        Retrieves the private key associated with a given name.

        :param name: The identifier for the key pair.
        :return: The private key.
        """
        return self.keys[name]['private_key']
