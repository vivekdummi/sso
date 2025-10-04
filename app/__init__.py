from flask import Flask
# from flask_mysql_connector import MySQL
from flask_mysqldb import MySQL
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
import subprocess
import click
import os


mysql = MySQL()
login_manager = LoginManager()

base_dir = os.path.dirname(os.path.dirname(__file__))

# Key storage paths
KEY_DIR = os.path.join(base_dir, 'keys')
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    mysql.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # Register CLI command
    register_cli(app)


    return app



def register_cli(app):
    @app.cli.command("generate-keys")
    @click.option(
        "--overwrite",
        is_flag=True,
        help="Overwrite existing keys if they exist.",
    )
    def generate_keys(overwrite=False):
        """Generate RSA private and public keys using OpenSSL."""

        # Check if OpenSSL is installed
        try:
            result = subprocess.run(
                ["openssl", "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            click.echo(f"OpenSSL version: {result.stdout.decode().strip()}")
        except FileNotFoundError as exc:
            raise RuntimeError(
                "OpenSSL is not installed or not available in PATH.",
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"Failed to execute OpenSSL: {exc.stderr.decode().strip()}",
            ) from exc

        # Ensure the output directory exists
        if not os.path.exists(KEY_DIR):
            os.makedirs(KEY_DIR)

        # Check if the files already exist
        if (
            os.path.exists(PRIVATE_KEY_PATH) or os.path.exists(PUBLIC_KEY_PATH)
        ) and not overwrite:
            raise Exception(
                "Key files already exist. Use --overwrite to overwrite.",
            )
        click.echo("Overwriting existing PEM keys.")

        # Generate private key
        try:
            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-out",
                    PRIVATE_KEY_PATH,
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                ],
                check=True,
            )
            click.echo(f"Private key generated at: {PRIVATE_KEY_PATH}")
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"Failed to generate private key: {exc}") from exc

        # Generate public key
        try:
            subprocess.run(
                [
                    "openssl",
                    "rsa",
                    "-pubout",
                    "-in",
                    PRIVATE_KEY_PATH,
                    "-out",
                    PUBLIC_KEY_PATH,
                ],
                check=True,
            )
            click.echo(f"Public key generated at: {PUBLIC_KEY_PATH}")
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"Failed to generate public key: {exc}") from exc