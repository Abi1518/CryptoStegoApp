
from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    session,
    jsonify,
    Response
)
from waitress import serve
import os
import uuid
import pickle
import secrets
from datetime import datetime

from PIL import Image

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from encryption.aes import (
    generate_key,
    encrypt_data
)

from encryption.rsa import (
    encrypt_key,
    generate_keys
)

from steganography.lsb import (
    encode_image
)

from decryption.decrypt import (
    recover_file
)

from security.integrity import (
    generate_hash
)

from database.db import (
    initialize_database,
    get_connection,
    add_history,
    get_user_history,
    get_user_stats
)


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)

# =========================================================
# DIRECTORIES
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

OUTPUT_FOLDER = os.path.join(
    BASE_DIR,
    "outputs"
)

KEY_FOLDER = os.path.join(
    BASE_DIR,
    "keys"
)

TEMP_FOLDER = os.path.join(
    BASE_DIR,
    "temp"
)


os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

os.makedirs(
    OUTPUT_FOLDER,
    exist_ok=True
)

os.makedirs(
    KEY_FOLDER,
    exist_ok=True
)

os.makedirs(
    TEMP_FOLDER,
    exist_ok=True
)


# =========================================================
# DATABASE
# =========================================================

initialize_database()


# =========================================================
# ALLOWED COVER IMAGES
# =========================================================

ALLOWED_COVERS = [

    "rose.jpg",

    "nature.avif",

    "ocean.jpg",

    "forest.jpg",

    "city.avif",

    "space.avif"

]


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required():

    return "user_id" in session


# =========================================================
# TEMPORARY SECRET CLEANUP
# =========================================================

def cleanup_temp_secret():

    temp_file = session.get(
        "temp_secret_file"
    )

    if temp_file:

        try:

            if os.path.exists(
                temp_file
            ):

                os.remove(
                    temp_file
                )

        except Exception as e:

            print(
                "Temporary secret cleanup error:",
                e
            )


    session.pop(
        "temp_secret_file",
        None
    )

    session.pop(
        "temp_secret_original_name",
        None
    )


def cleanup_temp_cover():
    temp_file = session.get("temp_cover_file")

    if temp_file:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except Exception as e:
            print("Temporary cover cleanup error:", e)

    session.pop("temp_cover_file", None)
    session.pop("temp_cover_original_name", None)

# =========================================================
# USER TEMP FILE CLEANUP
# =========================================================

def cleanup_user_temp_files(
    user_id
):

    if not user_id:

        return


    prefix = f"{user_id}_"


    try:

        for filename in os.listdir(
            TEMP_FOLDER
        ):

            if filename.startswith(
                prefix
            ):

                file_path = os.path.join(
                    TEMP_FOLDER,
                    filename
                )


                if os.path.isfile(
                    file_path
                ):

                    try:

                        os.remove(
                            file_path
                        )

                    except Exception as e:

                        print(
                            "Unable to remove temp file:",
                            file_path,
                            e
                        )


    except Exception as e:

        print(
            "User temporary folder cleanup error:",
            e
        )


# =========================================================
# LIBRARY COVER PATH
# =========================================================

def get_library_cover_path(
    cover_name
):

    if cover_name not in ALLOWED_COVERS:

        return None


    cover_path = os.path.join(

        BASE_DIR,

        "static",

        "images",

        "covers",

        cover_name

    )


    if not os.path.isfile(
        cover_path
    ):

        return None


    return cover_path


# =========================================================
# BUILD ENCRYPTION PAYLOAD
# =========================================================

def build_payload(
    data,
    filename,
    password
):

    # -----------------------------------------------------
    # File hash
    # -----------------------------------------------------

    file_hash = generate_hash(
        data
    )


    # -----------------------------------------------------
    # AES key
    # -----------------------------------------------------

    aes_key = generate_key()


    # -----------------------------------------------------
    # AES encryption
    #
    # IMPORTANT:
    # encrypt_data returns:
    # nonce, ciphertext, tag
    # -----------------------------------------------------

    nonce, ciphertext, tag = encrypt_data(
        data,
        aes_key
    )


    # -----------------------------------------------------
    # Unique RSA key ID
    # -----------------------------------------------------

    key_id = uuid.uuid4().hex


    # -----------------------------------------------------
    # Generate RSA keys
    # -----------------------------------------------------

    private_key, public_key = generate_keys(

        password.encode(),

        key_folder=KEY_FOLDER,

        key_id=key_id

    )


    # -----------------------------------------------------
    # Encrypt AES key with RSA
    # -----------------------------------------------------

    encrypted_aes_key = encrypt_key(

        aes_key,

        public_key

    )


    # -----------------------------------------------------
    # Build payload
    # -----------------------------------------------------

    payload = {

        "ciphertext": ciphertext,

        "aes_key": encrypted_aes_key,

        "nonce": nonce,

        "tag": tag,

        "hash": file_hash,

        "filename": filename,

        "key_id": key_id

    }


    return payload


# =========================================================
# PAYLOAD SIZE
# =========================================================

def get_payload_size(
    payload
):

    serialized_payload = pickle.dumps(

        payload,

        protocol=pickle.HIGHEST_PROTOCOL

    )


    return len(
        serialized_payload
    )


# =========================================================
# CACHE CONTROL
# =========================================================

@app.after_request
def add_no_cache_headers(
    response
):

    response.headers["Cache-Control"] = (

        "no-store, no-cache, "
        "must-revalidate, "
        "post-check=0, pre-check=0, "
        "max-age=0"

    )

    response.headers["Pragma"] = "no-cache"

    response.headers["Expires"] = "0"


    return response


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# PREPARE ENCRYPTION
# =========================================================

@app.route(
    "/prepare-encryption",
    methods=["POST"]
)
def prepare_encryption():

    if not login_required():

        return jsonify({

            "success": False,

            "message": "Please login first."

        }), 401


    secret_file = request.files.get(
        "secret_file"
    )


    if not secret_file:

        return jsonify({

            "success": False,

            "message": "Please select a secret file."

        }), 400


    if not secret_file.filename:

        return jsonify({

            "success": False,

            "message": "Invalid secret file."

        }), 400


    try:

        cleanup_temp_secret()


        original_name = os.path.basename(

            secret_file.filename

        )


        unique_name = (

            f"{session['user_id']}_"

            f"{uuid.uuid4().hex}_"

            f"{original_name}"

        )


        temp_path = os.path.join(

            TEMP_FOLDER,

            unique_name

        )


        secret_file.save(
            temp_path
        )


        session[
            "temp_secret_file"
        ] = temp_path


        session[
            "temp_secret_original_name"
        ] = original_name


        session.modified = True


        return jsonify({

            "success": True,

            "message":
                "Secret file prepared successfully."

        })


    except Exception as e:

        print(
            "Prepare encryption error:",
            e
        )


        return jsonify({

            "success": False,

            "message":
                "Unable to prepare the secret file."

        }), 500



@app.route("/prepare-cover", methods=["POST"])
def prepare_cover():
    if not login_required():
        return jsonify({
            "success": False,
            "message": "Please login first."
        }), 401

    uploaded_cover = request.files.get("cover_image")

    if not uploaded_cover or not uploaded_cover.filename:
        return jsonify({
            "success": False,
            "message": "Please select a cover image."
        }), 400

    try:
        # Validate the uploaded image before saving it.
        image = Image.open(uploaded_cover)
        image.verify()

        # Reset the stream after validation.
        uploaded_cover.stream.seek(0)

        original_name = os.path.basename(uploaded_cover.filename)
        unique_name = f"{session['user_id']}_{uuid.uuid4().hex}_{original_name}"
        temp_path = os.path.join(TEMP_FOLDER, unique_name)

        # Replace the previously saved temporary cover.
        cleanup_temp_cover()

        uploaded_cover.save(temp_path)

        session["temp_cover_file"] = temp_path
        session["temp_cover_original_name"] = original_name
        session.modified = True

        return jsonify({
            "success": True,
            "message": "Cover image prepared successfully.",
            "filename": original_name
        })

    except Exception as e:
        print("Prepare cover error:", e)
        return jsonify({
            "success": False,
            "message": "Unable to prepare the cover image."
        }), 400

# =========================================================
# COVER LIBRARY
# =========================================================

@app.route(
    "/cover-library"
)
def cover_library():

    if not login_required():

        return redirect(
            "/login"
        )


    return render_template(
        "cover_library.html"
    )


# =========================================================
# SELECT COVER
# =========================================================

@app.route(
    "/select-cover",
    methods=["POST"]
)
def select_cover():

    if not login_required():

        return redirect(
            "/login"
        )


    cover = request.form.get(
        "cover"
    )


    if not cover:

        return redirect(
            "/cover-library"
        )


    cover_path = get_library_cover_path(
        cover
    )


    if not cover_path:

        return redirect(
            "/cover-library"
        )


    session[
        "selected_cover"
    ] = cover


    session.modified = True


    return redirect(
        "/encrypt"
    )


# =========================================================
# CLEAR COVER
# =========================================================


@app.route("/clear-cover", methods=["POST"])
def clear_cover():
    if not login_required():
        return jsonify({
            "success": False,
            "message": "Please login first."
        }), 401

    # Clear the selected library cover
    session.pop("selected_cover", None)

    # Clear the saved device-cover details
    temp_cover_path = session.pop("temp_cover_file", None)
    session.pop("temp_cover_original_name", None)

    # Delete the saved device-cover file, if it exists
    if temp_cover_path and os.path.isfile(temp_cover_path):
        try:
            os.remove(temp_cover_path)
        except OSError:
            app.logger.exception("Unable to remove temporary cover file")

    session.modified = True

    return jsonify({
        "success": True
    })



@app.route("/clear-secret", methods=["POST"])
def clear_secret():
    if not login_required():
        return jsonify({
            "success": False,
            "message": "Please login first."
        }), 401

    cleanup_temp_secret()
    session.modified = True

    return jsonify({
        "success": True,
        "message": "Secret file removed successfully."
    })

# =========================================================
# ENCRYPT PAGE
# =========================================================


@app.route("/encrypt", methods=["GET"])
def encrypt_page():
    if not login_required():
        return redirect("/login")

    selected_cover = session.get("selected_cover")
    temp_secret_filename = session.get("temp_secret_original_name")
    temp_cover_filename = session.get("temp_cover_original_name")

    return render_template(
        "encrypt.html",
        selected_cover=selected_cover,
        temp_secret_filename=temp_secret_filename,
        temp_cover_filename=temp_cover_filename
    )


@app.route("/temporary-cover-preview", methods=["GET"])
def temporary_cover_preview():
    if not login_required():
        return redirect("/login")

    temp_cover_path = session.get("temp_cover_file")

    if not temp_cover_path or not os.path.isfile(temp_cover_path):
        return "Saved cover image not found.", 404

    try:
        with Image.open(temp_cover_path) as image:
            image.verify()

        return send_file(temp_cover_path, max_age=0)

    except Exception:
        return "Saved cover image is invalid.", 400

# =========================================================
# ENCRYPT FILE
# =========================================================

@app.route(
    "/encrypt",
    methods=["POST"]
)
def encrypt_file():

    if not login_required():

        return redirect(
            "/login"
        )


    user_id = session.get(
        "user_id"
    )


    password = request.form.get(
        "password",
        ""
    )


    if not password:

        return render_template(

            "error.html",

            message=
                "Please enter an encryption password."

        )


    uploaded_secret = request.files.get(
        "secret_file"
    )


    temp_secret_path = session.get(
        "temp_secret_file"
    )


    temp_secret_original_name = session.get(
        "temp_secret_original_name"
    )


    secret_path = None

    secret_filename = None


    try:

        # =================================================
        # SECRET FILE
        # =================================================

        if (

            uploaded_secret

            and uploaded_secret.filename

        ):

            secret_filename = os.path.basename(

                uploaded_secret.filename

            )


            secret_path = os.path.join(

                UPLOAD_FOLDER,

                secret_filename

            )


            uploaded_secret.save(
                secret_path
            )


        elif (

            temp_secret_path

            and os.path.isfile(
                temp_secret_path
            )

        ):

            secret_path = temp_secret_path


            secret_filename = (

                temp_secret_original_name

                or os.path.basename(
                    temp_secret_path
                )

            )


        else:

            return render_template(

                "error.html",

                message=
                    "Please select a secret file."

            )


        # =================================================
        # COVER
        # =================================================

        uploaded_cover = request.files.get(
            "cover_image"
        )


        selected_cover = session.get(
            "selected_cover"
        )

        temp_cover_path = session.get("temp_cover_file")
        temp_cover_original_name = session.get("temp_cover_original_name")
        cover_path = None


        # -------------------------------------------------
        # Device cover has priority
        # -------------------------------------------------

        if (

            uploaded_cover

            and uploaded_cover.filename

        ):

            cover_filename = os.path.basename(

                uploaded_cover.filename

            )


            uploaded_cover_path = os.path.join(

                UPLOAD_FOLDER,

                cover_filename

            )


            uploaded_cover.save(
                uploaded_cover_path
            )


            cover_path = uploaded_cover_path


            session.pop(
                "selected_cover",
                None
            )


            session.modified = True


        # -------------------------------------------------
        # Library cover
        # -------------------------------------------------

        elif selected_cover:

            cover_path = get_library_cover_path(

                selected_cover

            )


            if not cover_path:

                return render_template(

                    "error.html",

                    message=
                        "Selected cover image is invalid."

                )

        elif (
            temp_cover_path
             and os.path.isfile(temp_cover_path)
            ):
            cover_path = temp_cover_path
        else:

            return render_template(

                "error.html",

                message=
                    "Please select a cover image."

            )


        # =================================================
        # READ SECRET
        # =================================================

        with open(
            secret_path,
            "rb"
        ) as file:

            secret_data = file.read()


        # =================================================
        # COVER IMAGE
        # =================================================

        cover_image = Image.open(
            cover_path
        ).convert("RGB")


        width, height = cover_image.size


        capacity_bits = (

            width
            * height
            * 3

        )


        # =================================================
        # BUILD PAYLOAD
        # =================================================

        payload = build_payload(

            secret_data,

            secret_filename,

            password

        )


        payload_size = get_payload_size(
            payload
        )


        required_bits = (

            payload_size
            + 4

        ) * 8


        # =================================================
        # CAPACITY CHECK
        # =================================================

        if required_bits > capacity_bits:

            percentage = (

                required_bits
                / capacity_bits

            ) * 100


            # Remove RSA key created for failed operation

            key_id = payload.get(
                "key_id"
            )


            if key_id:

                for suffix in [

                    "_private.pem",
                    "_public.pem"

                ]:

                    key_path = os.path.join(

                        KEY_FOLDER,

                        f"{key_id}{suffix}"

                    )


                    try:

                        if os.path.exists(
                            key_path
                        ):

                            os.remove(
                                key_path
                            )

                    except Exception:
                        pass


            return render_template(

                "error.html",

                message=(

                    "Cover image does not have enough "
                    "capacity for this secret file. "

                    f"Required: {percentage:.2f}% "
                    "of available capacity."

                )

            )


        # =================================================
        # OUTPUT FILE
        # =================================================

        base_name = os.path.splitext(

            secret_filename

        )[0]


        output_filename = (

            f"{base_name}_stego.png"

        )


        output_path = os.path.join(

            OUTPUT_FOLDER,

            output_filename

        )


        # =================================================
        # ENCODE
        # =================================================

        encode_image(

            cover_path,

            payload,

            output_path

        )


        # =================================================
        # HISTORY
        #
        # Correct order:
        # user_id, filename, action, status
        # =================================================

        add_history(

            user_id,

            secret_filename,

            "Encryption",

            "Success"

        )


        # =================================================
        # CLEAN TEMP STATE
        # =================================================

        cleanup_temp_secret()
        cleanup_temp_cover()

        session.pop(
            "selected_cover",
            None
        )


        session.modified = True


        # =================================================
        # SUCCESS
        # =================================================

        return render_template(

            "success.html",

            filename=output_filename

        )


    except Exception as e:

        print(
            "Encryption error:",
            e
        )


        try:

            add_history(

                user_id,

                secret_filename or "Unknown",

                "Encryption",

                "Failed"

            )

        except Exception as history_error:

            print(
                "History error:",
                history_error
            )


        return render_template(

            "error.html",

            message=(

                "Encryption failed. "

                f"Error: {str(e)}"

            )

        )


# =========================================================
# DOWNLOAD
# =========================================================

@app.route(
    "/download/<path:filename>"
)
def download_file(
    filename
):

    if not login_required():

        return redirect(
            "/login"
        )


    safe_filename = os.path.basename(
        filename
    )


    file_path = os.path.join(

        OUTPUT_FOLDER,

        safe_filename

    )


    if not os.path.isfile(
        file_path
    ):

        return render_template(

            "error.html",

            message=
                "Requested file was not found."

        )


    return send_file(

        file_path,

        as_attachment=True,

        download_name=safe_filename

    )


# =========================================================
# DECRYPT
# =========================================================

@app.route(
    "/decrypt",
    methods=["GET", "POST"]
)
def decrypt():

    if not login_required():

        return redirect(
            "/login"
        )


    # =====================================================
    # GET
    # =====================================================

    if request.method == "GET":

        return render_template(
            "decrypt.html"
        )


    try:

        # =================================================
        # STEGO IMAGE
        # =================================================

        stego_file = request.files.get(
            "stego_file"
        )


        password = request.form.get(
            "password",
            ""
        )
        print("====================================")
        print("DECRYPT DEBUG")
        print("FILES:", request.files)
        print("FORM:", request.form)
        print("STEGO FILE:", stego_file)
        print("PASSWORD RECEIVED:", bool(password))
        print("====================================")

        if not stego_file:

            return render_template(

                "error.html",

                message=
                    "Please select a stego image."

            )


        if not stego_file.filename:

            return render_template(

                "error.html",

                message=
                    "Invalid stego image."

            )


        if not password:

            return render_template(

                "error.html",

                message=
                    "Please enter the decryption password."

            )


        # =================================================
        # SAVE STEGO IMAGE
        # =================================================

        filename = os.path.basename(

            stego_file.filename

        )


        stego_path = os.path.join(

            UPLOAD_FOLDER,

            filename

        )


        stego_file.save(
            stego_path
        )


        # =================================================
        # RECOVER FILE
        # =================================================

        recovered_data, recovered_filename = recover_file(

            stego_path,

            password

        )


        recovered_filename = os.path.basename(

            recovered_filename

        )


        # =================================================
        # SAVE RECOVERED FILE
        # =================================================

        output_path = os.path.join(

            OUTPUT_FOLDER,

            recovered_filename

        )


        with open(

            output_path,

            "wb"

        ) as file:

            file.write(
                recovered_data
            )


        # =================================================
        # HISTORY
        # =================================================

        add_history(

            session["user_id"],

            recovered_filename,

            "Decryption",

            "Success"

        )


        # =================================================
        # RESULT
        # =================================================

        return render_template(

            "result.html",

            filename=recovered_filename

        )


    except Exception as e:

        print(
            "Decryption error:",
            e
        )


        try:

            add_history(

                session["user_id"],

                "Unknown",

                "Decryption",

                "Failed"

            )

        except Exception as history_error:

            print(
                "History error:",
                history_error
            )


        return render_template(

            "error.html",

            message=(

                "Decryption failed. "

                f"Error: {str(e)}"

            )

        )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "GET":

        return render_template(
            "register.html"
        )


    username = request.form.get(
        "username",
        ""
    ).strip()


    email = request.form.get(
        "email",
        ""
    ).strip()


    password = request.form.get(
        "password",
        ""
    )


    if (
        not username
        or not email
        or not password
    ):

        return render_template(

            "error.html",

            message=
                "Please fill all required fields."

        )


    try:

        connection = get_connection()

        cursor = connection.cursor()


        cursor.execute(

            """

            SELECT id
            FROM users
            WHERE username = ?
               OR email = ?

            """,

            (
                username,
                email
            )

        )


        existing_user = cursor.fetchone()


        if existing_user:

            connection.close()


            return render_template(

                "error.html",

                message=
                    "Username or email already exists."

            )


        password_hash = generate_password_hash(
            password
        )


        cursor.execute(

            """

            INSERT INTO users
            (
                username,
                email,
                password
            )
            VALUES (?, ?, ?)

            """,

            (
                username,
                email,
                password_hash
            )

        )


        connection.commit()

        connection.close()


        return redirect(
            "/login"
        )


    except Exception as e:

        print(
            "Registration error:",
            e
        )


        return render_template(

            "error.html",

            message=
                "Registration failed."

        )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "GET":

        return render_template(
            "login.html"
        )


    username = request.form.get(
        "username",
        ""
    ).strip()


    password = request.form.get(
        "password",
        ""
    )


    if not username or not password:

        return render_template(

            "error.html",

            message=
                "Please enter username and password."

        )


    try:

        connection = get_connection()

        cursor = connection.cursor()


        cursor.execute(

            """

            SELECT id, username, password
            FROM users
            WHERE username = ?

            """,

            (username,)

        )


        user = cursor.fetchone()


        connection.close()


        if not user:

            return render_template(

                "error.html",

                message=
                    "Invalid username or password."

            )


        if not check_password_hash(

            user["password"],

            password

        ):

            return render_template(

                "error.html",

                message=
                    "Invalid username or password."

            )


        session.clear()


        session[
            "user_id"
        ] = user["id"]


        session[
            "username"
        ] = user["username"]


        session.modified = True


        return redirect(
            "/dashboard"
        )


    except Exception as e:

        print(
            "Login error:",
            e
        )


        return render_template(

            "error.html",

            message=
                "Login failed."

        )



# =========================================================
# REST API - REGISTER
# =========================================================

@app.route("/api/register", methods=["POST"])
def api_register():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "message": "JSON data is required."
        }), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({
            "success": False,
            "message": "Username, email and password are required."
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            SELECT id
            FROM users
            WHERE username = ? OR email = ?
            """,
            (username, email)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            return jsonify({
                "success": False,
                "message": "Username or email already exists."
            }), 409

        password_hash = generate_password_hash(
            password
        )

        cursor.execute(
            """
            INSERT INTO users
            (username, email, password)
            VALUES (?, ?, ?)
            """,
            (
                username,
                email,
                password_hash
            )
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Registration successful."
        }), 201

    except Exception as e:

        connection.rollback()

        return jsonify({
            "success": False,
            "message": "Registration failed."
        }), 500

    finally:

        connection.close()


# =========================================================
# REST API - LOGIN
# =========================================================

@app.route("/api/login", methods=["POST"])
def api_login():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "message": "JSON data is required."
        }), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "success": False,
            "message": "Username and password are required."
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT id, username, password
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        user = cursor.fetchone()

        if not user:
            return jsonify({
                "success": False,
                "message": "Invalid username or password."
            }), 401

        if not check_password_hash(
            user["password"],
            password
        ):
            return jsonify({
                "success": False,
                "message": "Invalid username or password."
            }), 401

        # Generate secure authentication token
        token = secrets.token_hex(32)

        # Store token in database
        cursor.execute(
            """
            INSERT INTO api_tokens
            (user_id, token, created_at)
            VALUES (?, ?, ?)
            """,
            (
                user["id"],
                token,
                datetime.now().isoformat()
            )
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Login successful.",
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"]
            }
        }), 200

    except Exception:
        connection.rollback()

        return jsonify({
            "success": False,
            "message": "Login failed."
        }), 500

    finally:
        connection.close()

@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():

    user = get_api_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    user_id = user["id"]

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_operations,

                SUM(
                    CASE
                        WHEN LOWER(TRIM(action)) = 'encryption'
                        THEN 1
                        ELSE 0
                    END
                ) AS encryption_count,

                SUM(
                    CASE
                        WHEN LOWER(TRIM(action)) = 'decryption'
                        THEN 1
                        ELSE 0
                    END
                ) AS decryption_count,

                SUM(
                    CASE
                        WHEN LOWER(TRIM(status)) = 'success'
                        THEN 1
                        ELSE 0
                    END
                ) AS success_count,

                SUM(
                    CASE
                        WHEN LOWER(TRIM(status)) = 'failed'
                        THEN 1
                        ELSE 0
                    END
                ) AS failed_count

            FROM history
            WHERE user_id = ?
            """,
            (user_id,)
        )

        stats = cursor.fetchone()

        return jsonify({
            "success": True,

            "user": {
                "id": user["id"],
                "username": user["username"]
            },

            "statistics": {
                "total_operations":
                    stats["total_operations"] or 0,

                "encryption_count":
                    stats["encryption_count"] or 0,

                "decryption_count":
                    stats["decryption_count"] or 0,

                "success_count":
                    stats["success_count"] or 0,

                "failed_count":
                    stats["failed_count"] or 0
            }
        }), 200

    except Exception as e:

        print("Dashboard API error:", e)

        return jsonify({
            "success": False,
            "message":
                "Unable to retrieve dashboard statistics."
        }), 500

    finally:
        connection.close()


# =========================================================
# API HISTORY
# =========================================================

@app.route("/api/history", methods=["GET"])
def api_history():

    # -----------------------------------------------------
    # 1. API authentication
    # -----------------------------------------------------

    user = get_api_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    user_id = user["id"]

    # -----------------------------------------------------
    # 2. Get user's history
    # -----------------------------------------------------

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            SELECT
                id,
                filename,
                action,
                date_time,
                status
            FROM history
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,)
        )

        rows = cursor.fetchall()

        history = []

        for row in rows:

            history.append({
                "id": row["id"],
                "filename": row["filename"],
                "action": row["action"],
                "date_time": row["date_time"],
                "status": row["status"]
            })

        return jsonify({
            "success": True,
            "history": history
        }), 200

    except Exception as e:

        print(
            "HISTORY API ERROR:",
            str(e)
        )

        return jsonify({
            "success": False,
            "message": "Unable to retrieve history."
        }), 500

    finally:

        connection.close()



# =========================================================
# API LOGOUT
# =========================================================

@app.route("/api/logout", methods=["POST"])
def api_logout():

    # -----------------------------------------------------
    # 1. Get API authentication
    # -----------------------------------------------------

    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    token = auth_header.split(" ", 1)[1].strip()

    if not token:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    # -----------------------------------------------------
    # 2. Delete current token
    # -----------------------------------------------------

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            DELETE FROM api_tokens
            WHERE token = ?
            """,
            (token,)
        )

        if cursor.rowcount == 0:

            connection.rollback()

            return jsonify({
                "success": False,
                "message": "Invalid or expired token."
            }), 401

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Logout successful."
        }), 200

    except Exception as e:

        connection.rollback()

        print(
            "LOGOUT API ERROR:",
            str(e)
        )

        return jsonify({
            "success": False,
            "message": "Logout failed."
        }), 500

    finally:

        connection.close()

# =========================================================
# API DOWNLOAD
# =========================================================

@app.route("/api/download/<path:filename>", methods=["GET"])
def api_download(filename):

    user = get_api_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    # Prevent path traversal and use only the filename
    safe_filename = os.path.basename(filename)

    file_path = os.path.join(
        OUTPUT_FOLDER,
        safe_filename
    )

    if not os.path.isfile(file_path):
        return jsonify({
            "success": False,
            "message": "File not found."
        }), 404

    try:
        # Read the complete file into memory
        with open(file_path, "rb") as file:
            file_data = file.read()

        file_size = len(file_data)

        print("====================================")
        print("DOWNLOAD API")
        print("Filename:", safe_filename)
        print("DOWNLOAD FILE SIZE:", file_size)
        print("DOWNLOAD BYTES READ:", len(file_data))
        print("====================================")

        response = Response(
            file_data,
            status=200,
            mimetype="image/png",
            direct_passthrough=True
        )

        response.headers["Content-Length"] = str(file_size)

        response.headers["Content-Disposition"] = (
            f'attachment; filename="{safe_filename}"'
        )

        return response

    except Exception as e:

        print("====================================")
        print("DOWNLOAD API ERROR:", str(e))
        print("====================================")

        return jsonify({
            "success": False,
            "message": "Unable to download file."
        }), 500

@app.route("/api/covers", methods=["GET"])
def api_covers():

    user = get_api_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    covers_folder = os.path.join(
        app.static_folder,
        "images",
        "covers"
    )

    allowed_extensions = {
        ".jpg",
        ".jpeg",
        ".png",
        ".webp",
        ".avif"
    }

    covers = []

    try:
        for filename in os.listdir(covers_folder):

            file_path = os.path.join(
                covers_folder,
                filename
            )

            if not os.path.isfile(file_path):
                continue

            extension = os.path.splitext(
                filename
            )[1].lower()

            if extension not in allowed_extensions:
                continue

            covers.append({
                "name": filename,
                "url": f"/static/images/covers/{filename}"
            })

        covers.sort(
            key=lambda cover: cover["name"].lower()
        )

        return jsonify({
            "success": True,
            "covers": covers
        }), 200

    except Exception as e:

        print("Cover API error:", e)

        return jsonify({
            "success": False,
            "message": "Unable to retrieve cover library."
        }), 500


@app.route("/api/capacity", methods=["POST"])
def api_capacity():

    user = get_api_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    try:

        # -------------------------------------------------
        # Get uploaded files
        # -------------------------------------------------

        secret_file = request.files.get("secret_file")
        cover_image = request.files.get("cover_image")

        if not secret_file:
            return jsonify({
                "success": False,
                "message": "Please select a secret file."
            }), 400

        if not cover_image or cover_image.filename == "":
            return jsonify({
                "success": False,
                "message": "Please select a cover image."
            }), 400


        # -------------------------------------------------
        # Read secret file
        # -------------------------------------------------

        secret_data = secret_file.read()

        secret_size = len(secret_data)

        secret_filename = os.path.basename(
            secret_file.filename
        )


        # -------------------------------------------------
        # Read cover image
        # -------------------------------------------------

        image = Image.open(cover_image).convert("RGB")

        width, height = image.size


        # -------------------------------------------------
        # Calculate steganography capacity
        # -------------------------------------------------

        capacity_bits = width * height * 3

        capacity_bytes = capacity_bits // 8


        # -------------------------------------------------
        # Build the REAL payload
        #
        # This is the same payload used during
        # actual encryption.
        # -------------------------------------------------

        temp_payload = build_payload(
            secret_data,
            secret_filename,
            "capacity-check"
        )


        # -------------------------------------------------
        # Get actual serialized payload size
        # -------------------------------------------------

        payload_bytes = get_payload_size(
            temp_payload
        )


        # -------------------------------------------------
        # Add 4-byte payload length header
        # -------------------------------------------------

        required_bytes = payload_bytes + 4

        required_bits = required_bytes * 8


        # -------------------------------------------------
        # Calculate usage
        # -------------------------------------------------

        usage_percentage = (
            required_bits / capacity_bits
        ) * 100


        # -------------------------------------------------
        # Calculate remaining capacity
        # -------------------------------------------------

        remaining_bits = (
            capacity_bits - required_bits
        )

        remaining_bytes = max(
            0,
            remaining_bits // 8
        )


        # -------------------------------------------------
        # Determine capacity status
        # -------------------------------------------------

        if required_bits > capacity_bits:

            status = "danger"

            message = (
                "Cover image is too small "
                "for this file."
            )

            can_encrypt = False

            fits = False

        elif usage_percentage >= 85:

            status = "warning"

            message = (
                "Cover image is almost full. "
                "A larger image is recommended."
            )

            can_encrypt = True

            fits = True

        else:

            status = "safe"

            message = (
                "Cover image has sufficient capacity."
            )

            can_encrypt = True

            fits = True


        # -------------------------------------------------
        # Remove temporary RSA keys
        # -------------------------------------------------

        key_id = temp_payload.get("key_id")

        if key_id:

            for suffix in [
                "_private.pem",
                "_public.pem"
            ]:

                key_path = os.path.join(
                    KEY_FOLDER,
                    f"{key_id}{suffix}"
                )

                try:

                    if os.path.exists(key_path):
                        os.remove(key_path)

                except Exception:
                    pass


        # -------------------------------------------------
        # Return capacity information
        # -------------------------------------------------

        return jsonify({

            "success": True,

            "width": width,

            "height": height,

            "secret_size": secret_size,

            "capacity_bytes": capacity_bytes,

            "payload_bytes": payload_bytes,

            "estimated_payload": payload_bytes,

            "required_bytes": required_bytes,

            "required_bits": required_bits,

            "percentage": round(
                usage_percentage,
                2
            ),

            "usage_percentage": round(
                usage_percentage,
                2
            ),

            "remaining_bytes": remaining_bytes,

            "fits": fits,

            "status": status,

            "can_encrypt": can_encrypt,

            "message": message

        }), 200


    except Exception as e:

        print(
            "CAPACITY API ERROR:",
            str(e)
        )

        return jsonify({

            "success": False,

            "message": str(e)

        }), 400

# =========================================================
# API ENCRYPT
# =========================================================


# =========================================================
# API ENCRYPT
# =========================================================

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():

    # -----------------------------------------------------
    # 1. API authentication
    # -----------------------------------------------------

    user = get_api_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    # -----------------------------------------------------
    # 2. Get uploaded data
    # -----------------------------------------------------

    secret_file = request.files.get("secret_file")
    cover_image = request.files.get("cover_image")
    password = request.form.get("password", "")

    if not secret_file:
        return jsonify({
            "success": False,
            "message": "Please select a secret file."
        }), 400

    if not cover_image or cover_image.filename == "":
        return jsonify({
            "success": False,
            "message": "Please select a cover image."
        }), 400

    if not password:
        return jsonify({
            "success": False,
            "message": "Password is required."
        }), 400

    # -----------------------------------------------------
    # 3. Variables for cleanup
    # -----------------------------------------------------

    key_id = None
    cover_path = None
    output_path = None

    try:

        # -------------------------------------------------
        # 4. Read secret file
        # -------------------------------------------------

        secret_data = secret_file.read()

        if not secret_data:
            return jsonify({
                "success": False,
                "message": "Secret file is empty."
            }), 400

        original_filename = secret_file.filename

        # -------------------------------------------------
        # 5. Save uploaded cover temporarily
        # -------------------------------------------------

        cover_filename = (
            f"{uuid.uuid4().hex}_"
            f"{cover_image.filename}"
        )

        cover_path = os.path.join(
            UPLOAD_FOLDER,
            cover_filename
        )

        cover_image.save(cover_path)

        # -------------------------------------------------
        # 6. Open cover image
        # -------------------------------------------------

        image = Image.open(
            cover_path
        ).convert("RGB")

        # -------------------------------------------------
        # 7. Build encrypted payload
        # -------------------------------------------------

        payload = build_payload(
            secret_data,
            original_filename,
            password
        )

        key_id = payload["key_id"]

        # -------------------------------------------------
        # 8. Calculate actual payload size
        # -------------------------------------------------

        payload_size = get_payload_size(
            payload
        )

        # -------------------------------------------------
        # 9. Calculate image capacity
        # -------------------------------------------------

        capacity_bits = (
            image.width *
            image.height *
            3
        )

        required_bits = (
            payload_size + 4
        ) * 8

        # -------------------------------------------------
        # 10. Check capacity
        # -------------------------------------------------

        if required_bits > capacity_bits:

            private_key_path = os.path.join(
                KEY_FOLDER,
                f"{key_id}_private.pem"
            )

            public_key_path = os.path.join(
                KEY_FOLDER,
                f"{key_id}_public.pem"
            )

            for key_path in [
                private_key_path,
                public_key_path
            ]:

                if os.path.exists(key_path):
                    os.remove(key_path)

            return jsonify({
                "success": False,
                "message": (
                    "Cover image is too small "
                    "for this file."
                )
            }), 400

        # -------------------------------------------------
        # 11. Create output filename
        # -------------------------------------------------

        base_name = os.path.splitext(
            original_filename
        )[0]

        output_filename = (
            f"{base_name}_stego.png"
        )

        output_path = os.path.join(
            OUTPUT_FOLDER,
            output_filename
        )

        # -------------------------------------------------
        # 12. Hide encrypted payload inside image
        # -------------------------------------------------

        encode_image(
            cover_path,
            payload,
            output_path
        )

        # -------------------------------------------------
        # 13. Add history
        # -------------------------------------------------

        add_history(
            user["id"],
            original_filename,
            "Encryption",
            "Success"
        )

        # -------------------------------------------------
        # 14. Remove temporary uploaded cover
        # -------------------------------------------------

        if os.path.exists(cover_path):
            os.remove(cover_path)

        # -------------------------------------------------
        # 15. Successful response
        # -------------------------------------------------

        return jsonify({
            "success": True,
            "message": (
                "File encrypted successfully."
            ),
            "filename": output_filename,
            "download_url": (
                f"/api/download/{output_filename}"
            ),
            "key_id": key_id,
            "payload_size": payload_size
        }), 200

    # -----------------------------------------------------
    # 16. Handle encryption errors
    # -----------------------------------------------------

    except Exception as e:

        print(
            "ENCRYPT API ERROR:",
            str(e)
        )

        # -------------------------------------------------
        # Remove temporary cover
        # -------------------------------------------------

        if cover_path:

            if os.path.exists(cover_path):

                try:
                    os.remove(cover_path)
                except Exception:
                    pass

        # -------------------------------------------------
        # Remove generated RSA keys
        # -------------------------------------------------

        if key_id:

            private_key_path = os.path.join(
                KEY_FOLDER,
                f"{key_id}_private.pem"
            )

            public_key_path = os.path.join(
                KEY_FOLDER,
                f"{key_id}_public.pem"
            )

            for key_path in [
                private_key_path,
                public_key_path
            ]:

                if os.path.exists(key_path):

                    try:
                        os.remove(key_path)
                    except Exception:
                        pass

        # -------------------------------------------------
        # Remove incomplete output
        # -------------------------------------------------

        if output_path:

            if os.path.exists(output_path):

                try:
                    os.remove(output_path)
                except Exception:
                    pass

        # -------------------------------------------------
        # Record failed operation
        # -------------------------------------------------

        try:

            add_history(
                user["id"],
                (
                    secret_file.filename
                    if secret_file
                    else "unknown"
                ),
                "Encryption",
                "Failed"
            )

        except Exception:
            pass

        # -------------------------------------------------
        # Return error
        # -------------------------------------------------

        return jsonify({
            "success": False,
            "message": "Encryption failed."
        }), 500



# =========================================================
# API DECRYPT
# =========================================================

@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():

    # -----------------------------------------------------
    # 1. API authentication
    # -----------------------------------------------------

    user = get_api_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    # -----------------------------------------------------
    # 2. Get uploaded stego image and password
    # -----------------------------------------------------

    stego_image = request.files.get("stego_image")
    password = request.form.get("password", "")

    if not stego_image:
        return jsonify({
            "success": False,
            "message": "Please select a stego image."
        }), 400

    if stego_image.filename == "":
        return jsonify({
            "success": False,
            "message": "Please select a stego image."
        }), 400

    if not password:
        return jsonify({
            "success": False,
            "message": "Password is required."
        }), 400

    stego_path = None
    output_path = None

    try:

        # -------------------------------------------------
        # 3. Save uploaded stego image temporarily
        # -------------------------------------------------

        safe_filename = (
            f"{uuid.uuid4().hex}_"
            f"{stego_image.filename}"
        )

        stego_path = os.path.join(
            UPLOAD_FOLDER,
            safe_filename
        )

        stego_image.save(stego_path)

        # -------------------------------------------------
        # 4. Recover original file
        # -------------------------------------------------

        original_data, original_filename = recover_file(
            stego_path,
            password
        )

        # -------------------------------------------------
        # 5. Create output filename
        # -------------------------------------------------

        output_path = os.path.join(
            OUTPUT_FOLDER,
            original_filename
        )

        # -------------------------------------------------
        # 6. Save recovered file
        # -------------------------------------------------

        with open(output_path, "wb") as file:
            file.write(original_data)

        # -------------------------------------------------
        # 7. Add successful history
        # -------------------------------------------------

        add_history(
            user["id"],
            original_filename,
            "Decryption",
            "Success"
        )

        # -------------------------------------------------
        # 8. Remove temporary stego image
        # -------------------------------------------------

        if os.path.exists(stego_path):
            os.remove(stego_path)

        # -------------------------------------------------
        # 9. Return successful response
        # -------------------------------------------------

        return jsonify({
            "success": True,
            "message": "File decrypted successfully.",
            "filename": original_filename,
            "download_url": (
                f"/api/download/{original_filename}"
            )
        }), 200

    except Exception as e:

        print(
            "DECRYPT API ERROR:",
            str(e)
        )

        # -------------------------------------------------
        # Remove temporary stego image
        # -------------------------------------------------

        if stego_path:

            if os.path.exists(stego_path):

                try:
                    os.remove(stego_path)
                except Exception:
                    pass

        # -------------------------------------------------
        # Remove incomplete recovered file
        # -------------------------------------------------

        if output_path:

            if os.path.exists(output_path):

                try:
                    os.remove(output_path)
                except Exception:
                    pass

        # -------------------------------------------------
        # Add failed history
        # -------------------------------------------------

        try:

            add_history(
                user["id"],
                (
                    stego_image.filename
                    if stego_image
                    else "unknown"
                ),
                "Decryption",
                "Failed"
            )

        except Exception:
            pass

        # -------------------------------------------------
        # Return error
        # -------------------------------------------------

        return jsonify({
            "success": False,
            "message": "Decryption failed."
        }), 500



def get_api_user():
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()

    if not token:
        return None

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT users.id, users.username
            FROM api_tokens
            JOIN users ON users.id = api_tokens.user_id
            WHERE api_tokens.token = ?
            """,
            (token,)
        )

        return cursor.fetchone()

    finally:
        connection.close()

@app.route("/api/test-auth", methods=["GET"])
def api_test_auth():

    user = get_api_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    return jsonify({
        "success": True,
        "message": "Authentication successful.",
        "user": {
            "id": user["id"],
            "username": user["username"]
        }
    }), 200
# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout"
)
def logout():

    user_id = session.get(
        "user_id"
    )


    cleanup_temp_secret()


    cleanup_user_temp_files(
        user_id
    )


    session.clear()


    return redirect(
        "/login"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route(
    "/dashboard"
)
def dashboard():

    if not login_required():

        return redirect(
            "/login"
        )


    user_id = session.get(
        "user_id"
    )


    stats = get_user_stats(
        user_id
    )


    return render_template(

        "dashboard.html",

        username=session.get(
            "username"
        ),

        stats=stats

    )


# =========================================================
# HISTORY
# =========================================================

@app.route(
    "/history"
)
def history():

    if not login_required():

        return redirect(
            "/login"
        )


    user_id = session.get(
        "user_id"
    )


    history_data = get_user_history(
        user_id
    )


    return render_template(

        "history.html",

        history=history_data

    )


# =========================================================
# CAPACITY CHECK
# =========================================================

@app.route(
    "/check-capacity",
    methods=["POST"]
)
def check_capacity():

    if not login_required():

        return jsonify({

            "success": False,

            "message":
                "Please login first."

        }), 401


    try:

        # =================================================
        # SECRET FILE
        # =================================================

        uploaded_secret = request.files.get(
            "secret_file"
        )


        temp_secret_path = session.get(
            "temp_secret_file"
        )


        temp_secret_original_name = session.get(
            "temp_secret_original_name"
        )


        secret_data = None

        secret_filename = None


        if (

            uploaded_secret

            and uploaded_secret.filename

        ):

            secret_data = uploaded_secret.read()


            secret_filename = os.path.basename(

                uploaded_secret.filename

            )


        elif (

            temp_secret_path

            and os.path.isfile(
                temp_secret_path
            )

        ):

            with open(

                temp_secret_path,

                "rb"

            ) as file:

                secret_data = file.read()


            secret_filename = (

                temp_secret_original_name

                or os.path.basename(
                    temp_secret_path
                )

            )


        else:

            return jsonify({

                "success": False,

                "message":
                    "Please select a secret file."

            }), 400


        # =================================================
        # COVER
        # =================================================

        uploaded_cover = request.files.get(
            "cover_image"
        )


        selected_cover = session.get(
            "selected_cover"
        )


        cover_image = None


        if (

            uploaded_cover

            and uploaded_cover.filename

        ):

            try:

                cover_image = Image.open(

                    uploaded_cover

                ).convert("RGB")


            except Exception:

                return jsonify({

                    "success": False,

                    "message":
                        "Invalid cover image."

                }), 400


        elif selected_cover:

            cover_path = get_library_cover_path(

                selected_cover

            )


            if not cover_path:

                return jsonify({

                    "success": False,

                    "message":
                        "Selected cover image is invalid."

                }), 400


            cover_image = Image.open(

                cover_path

            ).convert("RGB")



        elif (
            session.get("temp_cover_file")
            and os.path.isfile(session.get("temp_cover_file"))
            ):
            try:
                cover_image = Image.open(
                    session["temp_cover_file"]
                ).convert("RGB")
            except Exception:
                return jsonify({
                 "success": False,
                    "message": "Saved cover image is invalid."
                }), 400

        else:
            return jsonify({
            "success": False,
            "message": "Please select a cover image."
        }), 400


        # =================================================
        # CAPACITY
        # =================================================

        width, height = cover_image.size


        capacity_bits = (

            width
            * height
            * 3

        )


        capacity_bytes = (

            capacity_bits // 8

        )


        # =================================================
        # BUILD TEMP PAYLOAD
        # =================================================

        # A temporary payload is used only to estimate
        # the actual serialized size.

        temp_payload = build_payload(

            secret_data,

            secret_filename,

            "capacity-check"

        )


        payload_bytes = get_payload_size(

            temp_payload

        )


        required_bytes = payload_bytes + 4


        required_bits = required_bytes * 8


        percentage = (

            required_bits
            / capacity_bits
            * 100

        )


        fits = (

            required_bits
            <= capacity_bits

        )


        # -------------------------------------------------
        # Remove temporary RSA keys generated only for
        # capacity estimation.
        # -------------------------------------------------

        key_id = temp_payload.get(
            "key_id"
        )


        if key_id:

            for suffix in [

                "_private.pem",
                "_public.pem"

            ]:

                key_path = os.path.join(

                    KEY_FOLDER,

                    f"{key_id}{suffix}"

                )


                try:

                    if os.path.exists(
                        key_path
                    ):

                        os.remove(
                            key_path
                        )

                except Exception:

                    pass


        return jsonify({

            "success": True,

            "width": width,

            "height": height,

            "secret_size": len(secret_data),

            "capacity_bytes":
                capacity_bytes,

            "payload_bytes":
                payload_bytes,

            "required_bytes":
                required_bytes,

            "required_bits":
                required_bits,

            "percentage":
                round(
                    percentage,
                    2
                ),

            "remaining_bytes": max(
        0,
        (capacity_bits - required_bits) // 8
           ),

            "fits": fits,

            "status": (
             "Not enough capacity"
                if not fits
                else "warning"
                if percentage >= 85
                else "Enough capacity"
            ),

            "message": (
            "Not enough capacity! Choose a larger cover image."
            if not fits
            else "Warning: Image capacity usage is high."
            if percentage >= 85
            else "Enough capacity available."
            )

        })


    except Exception as e:

        print(
            "Capacity check error:",
            e
        )


        return jsonify({

            "success": False,

            "message":
                str(e)

        }), 500


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    print("====================================")
    print("CryptoStego Server Started")
    print("Website: http://127.0.0.1:5000")
    print("API:     http://127.0.0.1:5000/api")
    print("====================================")

    serve(
        app,
        host="0.0.0.0",
        port=5000
    )
