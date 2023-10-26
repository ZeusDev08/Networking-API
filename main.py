from imports import *

app = Flask(__name__)
app.secret_key = "hola123!"
@app.route("/")
def home():
    data = {
        "msg": "Welcome to Jose's network API"
    }

    return jsonify(data), 200

load_dotenv()

def login_required(f):
    @wraps(f)

    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            data = {
                "msg": "You gotta log in or register"
            }

            return jsonify(data), 401
        return f(*args, **kwargs)
    return decorated_function

def banned_ips(f):
    wraps(f)

    def decorated_function(*args, **kwargs):
        ip = socket.gethostname()
        ip2 = socket.gethostbyname(ip)
        print(ip2)

        banned_ips = [
            "192.168.1.1",
        ]

        if ip2 in banned_ips:
            return jsonify(data={"[BANNED]": "You are banned."}), 401
        return f(*args, **kwargs)
    return decorated_function

def save_ips(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        first = socket.gethostname()
        ip = socket.gethostbyname(first)

        with open("./ips.txt", "w") as file:
            file.write(f"{ip}\n")
        
        return f(*args, **kwargs)
    return decorated_function



def generar_numero():
    numero = random.randint(1111111111111111111111111, 9999999999999999999999999999999999)
    print(numero)
    return numero
def generar_token(usuario_id):
    expiracion = datetime.utcnow() + timedelta(hours=1)  # Expira en 1 hora
    payload = {'usuario_id': usuario_id, 'exp': expiracion}
    token = jwt.encode(payload, str(generar_numero()), algorithm='HS256')
    return token


def generar_uuid():
    return str(uuid.uuid4())





@app.route("/gen-token", methods=["GET"])
@login_required
def gen_token():
    token = generar_token(generar_uuid())
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io/",
        auth_token = auth_token
    )

    with client:
        query = client.execute("INSERT INTO tokens VALUES (?)", (token,))
    
    data = {
        "token": f"{token}"
    }

    return jsonify(data), 200



import os

@app.route("/register", methods=["POST"])
def register():
    username = request.args.get("username")
    password = request.args.get("password")

    if username == None or username == "":
        data = {
            "msg": "Username Required"
        }

        return jsonify(data), 400
    if password == None or password == "":
        data = {
            "msg": "Password is required"
        }

        return jsonify(data), 400
    else:
        auth_token = os.getenv("AUTH_TOKEN")
        client = libsql_client.create_client_sync(
            url="libsql://login-reg-zeusdev08.turso.io/",
            auth_token=auth_token
        )

        with client:
            try:
                query1 = client.execute("SELECT username FROM register")
                for row in query1:
                    if row[0] == username:
                        data = {
                            "username": "Already taken"
                        }

                        return jsonify(data), 400
                
                if len(password) <= 8:
                    return jsonify(data={"msg": "Password has less than 8 characters"})
                
                def check_content(password):
                    mayuscula = bool(re.search(r'[A-Z]', password))
                    numbers = bool(re.search(r'\d', password))
                    special_signs = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

                    return mayuscula and numbers and special_signs
                    
                if check_content(password):
                    encrypted_password = hashlib.sha256(password.encode("UTF-8")).hexdigest()
                        
                    query = client.execute("INSERT INTO register VALUES (?, ?)", (username, encrypted_password,))

                    data = {
                        "Registed successfuly": "a"
                    }

                    return jsonify(data), 200
                else:
                    data = {
                        "msg": "Password doesnt meet the requirements"
                    }

                    return jsonify(data), 400
            except Exception as e:
                print(e)

                data = {
                    "msg": f"Error {e}"
                }

                return jsonify(data), 500


@app.route("/login", methods=["POST"])
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    if username == "" or username == None:
        data = {
            "msg": "Usuario requerido"
        }

        return jsonify(data), 400
    if password == "" or password == None:
        data = {
            "msg": "Contraseña requerida"
        }

        return jsonify(data), 400
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url="libsql://login-reg-zeusdev08.turso.io/",
        auth_token=auth_token
    )

    with client:
        try:
            query = client.execute("SELECT username, password FROM register")
            encrypted_password = hashlib.sha256(password.encode("UTF-8")).hexdigest()
            user = [row[0] for row in query]
            passwd = [row[1] for row in query]
            if username in user and encrypted_password in passwd:
                print(encrypted_password)
                session['logged_in'] = True
                data = {
                    "msg": "Logged in"
                }
                return jsonify(data), 200
            else:
                data = {
                    "msg": "Wrong credentials"
                }
                return jsonify(data), 401
        except Exception as e:
            print(e)
            
            data = {
                "msg": "Error contact dev"
            }

            return jsonify(data), 500
    





@app.route("/api/v1/theory")
@save_ips
@banned_ips
@login_required
def show_files():
    path = "D:/NETWORKING API/theory"
    files = os.listdir(path)
    token = request.args.get("token")

    if token == None or token == "":
        return jsonify(data={"msg": "Token required"}), 401 
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url="libsql://login-reg-zeusdev08.turso.io",
        auth_token=auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")
            tokens = [row[0] for row in query]

            if token in tokens:
                file_links = []
                for file in files:
                    file_links.append({
                        'name': file,
                        'download_link': f"/api/v1/theory/{file}",
                        'view_link': f"/api/v1/theory/view/{file}"
                    })

                return render_template('files.html', files=file_links)
            
        except Exception as e:
            print(f"Error: {e}")

    return "Unknown error", 500

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    return jsonify(data={"msg": "logged_out"}), 200



@app.route("/api/v1/theory/view/<filename>")
def view_file(filename):
    path = "/home/ByteDev/mysite/theory"
    return send_from_directory(path, filename)

@app.route("/api/v1/theory/<filename>")
def download_file(filename):
    path = "/home/ByteDev/mysite/theory"
    return send_from_directory(path, filename, as_attachment=True)
 

@app.route("/api/v10/networking/ip-calculator/get-class/<ip>")
def ip_calculator(ip: str):

    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                ip1 = ip
                print(ip1.split("."))
                

                splitted_ip = ip1.split(".")
                
                
                if 1 <= int(splitted_ip[0]) <= 127 and 0 <= int(splitted_ip[1]) <= 255:
                    data = {
                        "Clase": "A",
                        "Default Mask": "255.0.0.0"
                    }
                elif 128 <= int(splitted_ip[0]) <= 191 and 0 <= int(splitted_ip[1]) <= 255:
                    data = {
                        "Clase": "B",
                        "Default Mask": "255.255.0.0"
                    }
                elif 192 <= int(splitted_ip[0]) <= 223 and 0 <= int(splitted_ip[1]) <= 255:
                    data = {
                        "Clase": "C",
                        "Default Mask": "255.255.255.0"
                    }
                else:
                    data = {
                        "Error": "Dirección IP fuera de los rangos conocidos"
                    }

                return jsonify(data), 200
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)

            data = {
                "Error": "Contact the developer of this service to fix it"
            }

            return jsonify(data), 500
    

@app.route("/api/v10/maths/binary/<num>")
def convert_bin(num: str):
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                numero = int(num)

                binario = bin(numero)

                data = {
                    "Response": binario.replace("0b", "")
                }

                return jsonify(data), 200
        except Exception as e:
            print(e)

            data = {
                "Error": "Contact the developer of this service to fix it"
            }

            return jsonify(data), 500



@app.route("/api/v10/maths/binary/convert-bin-num/<bin>")
def reverse_bin(bin):

    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                binario = str(bin)
                result = 0
                for position, digit in enumerate(binario[::-1]):
                    digit1 = int(digit)
                    algorithm = digit1 * 2 ** position

                    result += algorithm
                
                data = {
                    "Response": result
                }

                return jsonify(data), 200
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 200
        except Exception as e:
            print(e)

            data = {
                "msg": "Error contact the dev"
            }

            return jsonify(data), 500


@app.route("/api/v10/networking/mask-to-bin/<mask>")
def check_subnets(mask: str):
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                mascara = mask.split(".")
                
                
                primerNum = bin(int(mascara[0])).replace("0b", "")
                segundoNum = bin(int(mascara[1])).replace("0b", "")
                tercerNum = bin(int(mascara[2])).replace("0b", "")
                cuartoNum = bin(int(mascara[3])).replace("0b", "")

                print(primerNum)
                print(segundoNum)
                print(tercerNum)
                print(cuartoNum)
                
                mask_in_bin = f"{primerNum}.{segundoNum}.{tercerNum}.{cuartoNum}"
                print(mask_in_bin)



                    
                data = {
                    "Response": f"{mask_in_bin}"
                }

                return jsonify(data), 401
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)

            data = {
                "Error": "Contact a dev"
            }

            return jsonify(data), 500
        

@app.route("/api/v10/networking/wildcard/<mask>")
def wildcard(mask: str):

    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                mascara = mask.split(".")

                bin1 = bin(int(mascara[0]))[2:].zfill(8)
                bin2 = bin(int(mascara[1]))[2:].zfill(8)
                bin3 = bin(int(mascara[2]))[2:].zfill(8)
                bin4 = bin(int(mascara[3]))[2:].zfill(8)

                # replace each element for 0 if its a 1 and if its a 0 replace for 1
                bin1 = ''.join(['1' if b == '0' else '0' for b in bin1])
                bin2 = ''.join(['1' if b == '0' else '0' for b in bin2])
                bin3 = ''.join(['1' if b == '0' else '0' for b in bin3])
                bin4 = ''.join(['1' if b == '0' else '0' for b in bin4])    
                
                

                def convert_bin_to_base10(numero: str):
                    binario = numero
                    result = 0
                    for position, digit in enumerate(binario[::-1]):
                        digit1 = int(digit)
                        algorithm = digit1 * 2 ** position

                        result += algorithm
                    
                    return result

                bin1 = convert_bin_to_base10(bin1)
                bin2 = convert_bin_to_base10(bin2)
                bin3 = convert_bin_to_base10(bin3)
                bin4 = convert_bin_to_base10(bin4)

                data = {
                    "response": {
                        "msg": f"{bin1}.{bin2}.{bin3}.{bin4}"
                    }
                }

                return jsonify(data), 200
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)

            data = {
                "Error": "Contact a dev"
            }

            return jsonify(data), 500


@app.route("/api/v10/networking/calculate-hosts/<mask>")
def calculate_hosts(mask: str):
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                mascara = mask.split(".")
                bin1 = bin(int(mascara[0]))[2:].zfill(8)
                bin2 = bin(int(mascara[1]))[2:].zfill(8)
                bin3 = bin(int(mascara[2]))[2:].zfill(8)
                bin4 = bin(int(mascara[3]))[2:].zfill(8)

                # función zfill(8) rellena con 0 hasta que el tamaño sea igual a 8

                
                contador1 = int(bin1.count("0"))
                contador2 = int(bin2.count("0"))
                contador3 = int(bin3.count("0"))
                contador4 = int(bin4.count("0"))

                contador = contador1 + contador2 + contador3 + contador4
                algorithm = 2 ** contador - 2

                data = {
                    "msg": {
                        "hosts": algorithm
                    }
                }
                    
                

                return jsonify(data), 200
        except Exception as e:
            print(e)

            data = {
                "msg": "error contact DEV"
            }

            return jsonify(data), 500
        

@app.route("/api/v10/networking/subnets/<ip>")
def calculate_subnets(ip: str):
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:

                time1 = time.time()
                IP = ip.split(".")

                mascara = request.args.get("mask")

                if mascara == None or "":
                    return jsonify(data={"msg": "Mask required"}), 400
                mask = mascara.split(".")
                # IP TO BINARY
                bin1 = bin(int(IP[0]))[2:].zfill(8)
                bin2 = bin(int(IP[1]))[2:].zfill(8)
                bin3 = bin(int(IP[2]))[2:].zfill(8)
                bin4 = bin(int(IP[3]))[2:].zfill(8)

                print(bin4)
                # MASK TO BIN

                mask1 = bin(int(mask[0]))[2:].zfill(8)
                mask2 = bin(int(mask[1]))[2:].zfill(8)
                mask3 = bin(int(mask[2]))[2:].zfill(8)
                mask4 = bin(int(mask[3]))[2:].zfill(8)


                # calculate subnets
                req = requests.get(f"http://localhost:2000/api/v10/networking/ip-calculator/get-class/{ip}")
                json = req.json()
                time2 = time.time()
                operation = str(time1 - time2)
                print(operation[1:])
                if json["Clase"] == "C":
                    # Máscara /24
                    default_mask = "255.255.255.0"
                    modified_mask = mask
                    contador4 = int(mask4.count('1'))

                    contador = contador4
                    print(contador4)
                    algorithm = 2 ** contador
                    print(algorithm)
                    data = {
                        "msg": {
                            "mask in binary": f"{mask1}.{mask2}.{mask3}.{mask4}",
                            "IP in binary": f"{bin1}.{bin2}.{bin3}.{bin4}",
                            "subnets": algorithm,
                            "response_time": f"{operation[1:]} ms"
                        }
                    }

                    return jsonify(data), 200
                if json["Clase"] == "B":
                    default_mask = "255.255.0.0"
                    modified_mask = mask
                    contador3 = int(mask3.count("1"))
                    contador44 = int(mask4.count("1"))

                    contador = contador3 + contador44
                    print(contador)
                    algorithm = 2 ** contador

                    data = {
                        "msg": {
                            "mask in binary": f"{mask1}.{mask2}.{mask3}.{mask4}",
                            "IP in binary": f"{bin1}.{bin2}.{bin3}.{bin4}",
                            "subnets": algorithm,
                            "response_time": f"{operation[1:]} ms"
                        }
                    }

                    return jsonify(data), 200
                if json["Clase"] == "A":
                    default_mask = "255.0.0.0"
                    modified_mask = mask
                    contador2 = int(mask2.count("1"))
                    contador3 = int(mask3.count("1"))
                    contador4 = int(mask4.count("1"))

                    contador = contador2 + contador3 + contador4
                    algorithm = 2 ** contador

                    data = {
                        "msg": {
                            "mask in binary": f"{mask1}.{mask2}.{mask3}.{mask4}",
                            "IP in binary": f"{bin1}.{bin2}.{bin3}.{bin4}",
                            "subnets": algorithm,
                            "response_time": f"{operation[1:]} ms"
                        }
                    }

                    return jsonify(data), 200
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)

            data = {
                "msg": "Error contact DEV"
            }

            return jsonify(data), 500
        
            

@app.route("/api/v10/networking/jump-calculator/<ip>")
def jump_calculator(ip: str):

    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                IP = ip.split(".")

                mascara = request.args.get("mask")

                if mascara == None or "":
                    return jsonify(data={"msg":"Mask is required."}), 400
                
                mask = mascara.split(".")
                mask1 = bin(int(mask[0]))[2:].zfill(8)
                mask2 = bin(int(mask[1]))[2:].zfill(8)
                mask3 = bin(int(mask[2]))[2:].zfill(8)
                mask4 = bin(int(mask[3]))[2:].zfill(8)
                # Check IP class and depending of what class execute condition
                req = requests.get(f"http://localhost:2000/api/v10/networking/ip-calculator/get-class/{ip}")
                json = req.json()

                if json["Clase"] == "C":
                    def_mask = "255.255.255.0"

                    operation = 256 - int(mask[3])

                    data = {
                        "msg": {
                            "RESULT": operation
                        }
                    }

                    return jsonify(data), 200
                if json["Clase"] == "B":
                    def_mask = "255.255.0.0"
                    print(mask[2])
                    print(mask[3])
                    print(bin(int(mask[2]))[2:].zfill(8) != "0".zfill(8))
                    print(bin(int(mask[3]))[2:].zfill(8) != "0".zfill(8))
                    
                    if bin(int(mask[2]))[2:].zfill(8) != "0".zfill(8):
                        return 256 - int(mask[2])
                        
                    if bin(int(mask[3]))[2:].zfill(8) != "0".zfill(8):
                        return 256 - int(mask[3])

                    data = {
                        "msg": {
                            "WORKING ON THIS"
                        }
                    }

                    return jsonify(data), 401
                if json["Clase"] == "A":
                    data = {
                        "msg": {
                            "progress": "Still working",
                            "REQ CODE": "401"
                        }
                    }

                    return jsonify(data), 401
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)

            data = {
                "msg": "Error contact dev"
            }

            return jsonify(data), 500


# SEND MAIL WITH THEORY





# @app.route("/api/v2/networking/mailing/<email>")
# def send_mail(email: str):
#     data = {
#         "response": "email sent"
#     }
#     receiver = email
#     sender = "networkingapi@gmail.com"
#     subject = "prueba"
#     message = "python es god"

#     #funciona pero necesita OAUTH palazo
#     def send_email(sender_email, sender_password, receiver_email, subject, message):
#         try:
#             server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
#             server.login(sender_email, sender_password)
#             server.sendmail(sender_email, receiver_email, f"Subject: {subject}\n\n{message}")
#             server.quit()
#             print("Correo enviado exitosamente!")
#         except Exception as e:
#             print(f"Error al enviar el correo: {e}")
    
#     send_email(sender, "", receiver, subject, message)

#     return jsonify(data), 200
from scapy.all import *
@app.route("/api/v3/monitoring/network/connections")
def monitor():

    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                conexiones = psutil.net_connections()
                
                
                conexiones_info = {}
                for i, conexion in enumerate(conexiones):
                    try:
                        info = {
                            "Local Address": f"{conexion.laddr.ip}:{conexion.laddr.port}",
                            "Remote Address": f"{conexion.raddr.ip}:{conexion.raddr.port}",
                            "FD": conexion.fd,
                            "Type": conexion.type,
                            "Family": conexion.family,
                            "Status": conexion.status,
                            "info": {
                                "FD": {
                                    "msg": "if -1 means no descriptor, if positive value then has a descriptor of file"
                                },
                                "FAMILY": {
                                    "msg": "if 1 means IPv4, other nums IPv6"
                                },
                                "Type": {
                                    "msg": "1 means SOCK_STREAM, 2 means SOCK_DGRAM"
                                }
                            }
                        }
                        conexiones_info[f"Conexion {i+1}"] = info
                    except:
                        pass
                
                # Convertir el diccionario a JSON
                json_conexiones = json.dumps(conexiones_info, separators=(", ", ": "), indent=2)
                
                
                return Response(json_conexiones, content_type="application/json;charset=utf-8")
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)

            data = {
                "msg": "error contact DEV"
            }

            return jsonify(data), 500
            


def generate():
    while True:
        with app.app_context():
            net_stats = psutil.net_io_counters()
            data = {
                "bytes_sent": net_stats.bytes_sent,
                "bytes_recv": net_stats.bytes_recv
            }
            yield f"data: {jsonify(data)}\n\n"
            time.sleep(2)

@app.route('/api/v3/monitoring/network/bytes-sent-recv')
def check_bytes():
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                return Response(generate(), content_type='text/event-stream')
        except Exception as e:
            print(e)

            data = {
                "msg": "Error, contact dev"
            }

            return jsonify(data), 500

import speedtest
@app.route("/api/v3/monitoring/network/speedtest")
def speedtest_test():
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                st = speedtest.Speedtest()
                st.get_best_server()
                velocidad_subida = st.upload() / 10**6
                velocidad_bajada = st.download() / 10**6

                fecha_actual = datetime.now()
                save_test = request.args.get("save")
                print(save_test)
                if bool(save_test) == True:
                    conn = sqlite3.connect("historial_pruebas.db")
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO historial_pruebas (fecha, velocidad_subida, velocidad_bajada)
                        VALUES (?, ?, ?)
                    ''', (fecha_actual, velocidad_subida, velocidad_bajada))

                    conn.commit()
                    conn.close()

                    data = {
                        "Speedtest_results": {
                            "Subida": velocidad_subida,
                            "Bajada": velocidad_bajada
                        },
                        "Saved": save_test
                    }

                    return jsonify(data), 200
                elif bool(save_test) == False or None:


                    data = {
                        "Speedtest_results": {
                            "Subida": velocidad_subida,
                            "Bajada": velocidad_bajada
                        }
                    }
                
                    return jsonify(data), 200
                else:
                    data = {
                        "data": "Error"
                    }

                    return jsonify(data), 500
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)
            data = {
                "msg": "Error contact Dev"
            }

            return jsonify(data), 500

@app.route("/api/v3/monitoring/network/traceroute/<target>")
def traceroute(target, max_hops=30):
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                dns_resolver = requests.get(f"http://192.168.1.49:5000/api/v4/dns-resolver/{target}")
                res = dns_resolver.json()
                ip = res["Resolved DNS"]["IP"][2]
                final_ip = str(ip[0])
                ttl = 1
                while ttl <= max_hops:
                    # creación del paquete
                    pkt = IP(dst=final_ip, ttl=ttl) / ICMP()
                    # respuesta
                    reply = sr1(pkt, verbose=0, timeout=3)
                    # si la respuesta es nula entonces continuar
                    if reply is None:
                        continue
                    # si no printear el los "hops" y la respuesta
                    else:
                        print(f"{ttl}: {reply.src}")
                        # si el source pkt == a la tarquet entonces jumps = ttl
                        if reply.src == target:
                            data = {
                                "jumps": ttl
                            }

                            return jsonify(data), 200
                    
                    ttl += 1
                else:
                    data = {
                        "msg": "Unauthorized"
                    }

                    return jsonify(data), 401
        except Exception as e:
            print(e)
            data = {
                "msg": "Error contact dev"
            }

            return jsonify(data), 500
        


    
def capturar_paquete(packet_num):
    captured_packets = []

    def procesar_paquete(packet):
        # Comprobación si contiene una capa de transporte UDP o TCP
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            transport_layer = "TCP"
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            transport_layer = "UDP"
        else:
            src_port = None
            dst_port = None
            transport_layer = "OTRO"
        
        capas_osi = [str(layer) for layer in packet.layers()]

        print(capas_osi)
        if packet.haslayer(HTTPRequest):
            print(packet)
        
        if packet.haslayer(HTTPResponse):
            print(f"[HTTP_RESPONSE]: {packet}")
        
        if packet.haslayer(DNS):
            print(f"[DNS]: {packet}")

        
        packet_info = {
            "src_mac": packet.src,
            "dst_mac": packet.dst,
            "type": packet.type,
            "src_ip": packet[IP].src,  
            "dst_ip": packet[IP].dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "transport_layer": transport_layer,
            "osi": []
        }
        for layer in packet.layers():
            packet_info["osi"].append(str(layer))
        captured_packets.append(packet_info)


    try:
        sniff(prn=procesar_paquete, timeout=10, count=int(packet_num), filter="ip")
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    return jsonify({"captured_packets": captured_packets}), 200

    #return json.dumps(captured_packets), 200

@app.route("/api/v3/monitoring/network/sniffer")
def handle_captura_paquete():
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True
                    
            if token_found:
                packets = request.args.get("num_packs")
                result = capturar_paquete(packets)
                return result
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)

            data = {
                "msg": "Unauthorized"
            }

            return jsonify(data), 500

        

@app.route("/api/v3/monitoring/SSL-decoder/<url>")
def tls_detec(url: str):

    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True

            if token_found:
            # contexto: proporciona configuraciones y opciones para establecer conexiones seguras
                contexto = ssl.create_default_context()
                # Conexión segura y wrap_socket: envuelve el packet en una capa de seguridad SSL/TLS y el with asegura que termine de ejecutarse
                with contexto.wrap_socket(socket.socket(), server_hostname=url) as conexion:
                    conexion.connect((url, 443))
                    """
                        conexión segura usando SSL/TLS entre tu aplicación y el servidor especificado. La comunicación que sigue a esto será cifrada y segura.
                    """
                    # apreton de manos, intercambio de información
                    conexion.do_handshake()
                    #mnsaje cifrado
                    conexion.sendall(b'GET / HTTP/1.0\r\n\r\n')

                    respuesta = conexion.recv(4096)
                    cert_info = conexion.getpeercert()
                    
                    conexion.close()
                    data = {
                        "response": respuesta.decode(),
                        "Certificado": cert_info
                    }

                return jsonify(data), 200
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return
        except Exception as e:
            print(e)

            data = {
                "msg": "Error contact dev"
            }

            return jsonify(data), 500
        



@app.route("/api/v3/monitoring/snmp/send-packet/<ip>")
def snmp_sender(ip: str):
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True

            if token_found:
                try:
                    errorIndication, errorStatus, errorIndex, varBinds = next(
                        getCmd(
                            SnmpEngine(),
                            CommunityData("Networking API"),
                            UdpTransportTarget((ip, 161), timeout=5),
                            ContextData(),
                            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.3.0"))
                        )
                    )

                    if errorIndication:
                        print(f"Error: {errorIndication}")
                    elif errorStatus:
                        print(f"Error: {errorStatus.prettyPrint()}")
                    else:
                        for var in varBinds:
                            print(f"{var[0]} = {var[1]}\n")
                
                    data = {
                        "snmp": "sent"
                    }

                    return jsonify(data), 200
                except Exception as E:
                    data = {
                        "Error": f"ERROR {E}"
                    }

                    return jsonify(data), 500
            else:
                data = {
                    "msg": "Unauthorzied"
                }
                return jsonify(data), 401
        except Exception as e:
            print(e)
            data = {
                "msg": "Contact Dev"
            }

            return jsonify(data), 500
        
# LINK OIDS: https://www.10-strike.com/network-monitor/pro/useful-snmp-oids.shtml
# I have to ADD THIS FEATURE TO THE MAIN PROJECT
@app.route("/api/v4/dns-resolver/<url>")
def dns_resolver(url: str):
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True

            if token_found:
                dir = url

                data = socket.gethostbyname_ex(dir)

                data = {
                    "Resolved DNS": {
                        "IP": data
                    }
                }

                return jsonify(data), 200
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)

            data = {
                "Error": "Contact dev"
            }

            return jsonify(data), 500
        

@app.route("/api/v4/dns-resolver/ip-to-domain/<ip>")
def convert_ip_domain(ip: str):

    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True

            if token_found:
                data = socket.gethostbyaddr(ip)

                data1 = {
                    "Resolved DNS": {
                        "DNS": data[0],
                        "IP": data[2]
                    }
                }

                return jsonify(data1), 200
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 500
        except Exception as e:
            print(e)

            data = {
                "Error": "Contact Dev"
            }

            return jsonify(data), 500

def obtener_velocidad_conexion():
    # Obtener las estadísticas de red
    estadisticas_iniciales = psutil.net_io_counters()
    time.sleep(1)  # Esperar 1 segundo
    estadisticas_finales = psutil.net_io_counters()

    # Calcular la tasa de transferencia de datos
    velocidad_envio = (estadisticas_finales.bytes_sent - estadisticas_iniciales.bytes_sent) / 1  # bytes por segundo
    velocidad_recepcion = (estadisticas_finales.bytes_recv - estadisticas_iniciales.bytes_recv) / 1  # bytes por segundo

    return velocidad_envio, velocidad_recepcion


def obtener_ancho_de_banda():
    # Obtener las estadísticas de red
    estadisticas_iniciales = psutil.net_io_counters()
    time.sleep(1)  # Esperar 1 segundo
    estadisticas_finales = psutil.net_io_counters()

    # Calcular la tasa de transferencia de datos
    velocidad_envio = (estadisticas_finales.bytes_sent - estadisticas_iniciales.bytes_sent) / 1  # bytes por segundo
    velocidad_recepcion = (estadisticas_finales.bytes_recv - estadisticas_iniciales.bytes_recv) / 1  # bytes por segundo

    # Sumar las tasas de transferencia para obtener el ancho de banda total
    ancho_de_banda = velocidad_envio + velocidad_recepcion  # bytes por segundo

    return ancho_de_banda


@app.route("/api/v4/bandwith-calculator")
def calculate_bandwidth():
    token = request.args.get("token")

    if token is None or token == "":
        data = {
            "msg": "Unauthorized"
        }

        return jsonify(data), 200
    
    auth_token = os.getenv("AUTH_TOKEN")
    client = libsql_client.create_client_sync(
        url = "libsql://login-reg-zeusdev08.turso.io",
        auth_token = auth_token
    )

    with client:
        try:
            query = client.execute("select token from tokens")

            token_found = False

            for row in query:
                if row[0] == token:
                    token_found = True

            if token_found:
                # Obtener la velocidad de conexión y el ancho de banda
                velocidad_envio, velocidad_recepcion = obtener_velocidad_conexion()
                ancho_de_banda = obtener_ancho_de_banda()

                # Convertir a MB y GB
                velocidad_envio_MB = velocidad_envio / 10**6
                velocidad_recepcion_MB = velocidad_recepcion / 10**6
                ancho_de_banda_MB = ancho_de_banda / 10**6

                velocidad_envio_GB = velocidad_envio / 10**9
                velocidad_recepcion_GB = velocidad_recepcion / 10**9
                ancho_de_banda_GB = ancho_de_banda / 10**9

                data = {
                    "Bandwidth": {
                        "Velocidad de Envío (MB/s)": velocidad_envio_MB,
                        "Velocidad de Recepción (MB/s)": velocidad_recepcion_MB,
                        "Ancho de Banda Total (MB/s)": ancho_de_banda_MB,
                        "Velocidad de Envío (GB/s)": velocidad_envio_GB,
                        "Velocidad de Recepción (GB/s)": velocidad_recepcion_GB,
                        "Ancho de Banda Total (GB/s)": ancho_de_banda_GB
                    }
                }

                return jsonify(data), 200
            else:
                data = {
                    "msg": "Unauthorized"
                }

                return jsonify(data), 401
        except Exception as e:
            print(e)

            data = {
                "msg": "Error contact dev"
            }

            return jsonify(data), 500


@app.route("/api/contact/<msg>")
def send_modmail(msg: str):
    url = "https://discord.com/api/webhooks/1165989654097567816/FZaaJc3Oer0cspa2Yhf6HnoPVoaBCkt1wCnpcWbWn0VobRs7rbqtoyKxHl7FvNkwBSfA"
    embed = {
        "description": f"{msg}",
        "title": "NEW ISSUE"
    }

    data = {
        "content": "NEW ISSUE",
        "username": "NETWORKING API",
        "embeds": [
            embed
        ],
    }

    result = requests.post(url, json=data)

    try:
        result.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(e)

        data = {
            "error": "Error while sending the message"
        }
    else:
        data = {
            "SENT": "message sent, code {}".format(result.status_code)
        }

        return jsonify(data), 204

@app.route("/api/v1/networking/send-packet/icmp/<dst>")

def send_pkt_icmp(dst: str, ttl=30):
    msg = request.args.get("msg_to_send")
    pkt = IP(dst=dst, ttl=ttl) / ICMP() / msg
    # respuesta
    reply = sr1(pkt, verbose=0, timeout=3)
    payload = pkt.load

    print(payload)
    print(str(pkt))
    print(str(reply))

    data = {"Sent": f"{str(pkt)}", "Recv": f"{str(reply)}", "payload": str(payload)}

    return jsonify(data), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
        
