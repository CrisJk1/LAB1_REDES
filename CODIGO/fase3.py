from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

DELIMITADOR = b"<DELIMITADOR>"

tabs = 0
def log(level: str, msg: str):
    """
    Nombre funcion: log
    Parametros:
        - level: Nivel o contexto del mensaje a imprimir
        - msg: Mensaje a imprimir
    Descripcion:
        Funcion de utilidad para imprimir mensajes con indentacion segun el nivel de anidamiento
    """
    global tabs
    print("\t" * tabs + f"[{level}] {msg}")

def cifrar_mensaje(mensaje: bytes, priv_emisor: RSA.RsaKey, pub_receptor: RSA.RsaKey) -> bytes:
    """
    Nombre funcion: cifrar_mensaje
    Parametros:
        - mensaje: Informacion que se quiere enviar en bytes
        - priv_emisor: Objeto de Clave privada RSA del emisor
        - pub_receptor: Objeto de Clave publica RSA del receptor
    Descripcion:
        Funcion que se encarga de cifrar un mensaje utilizando la clave publica del receptor,
        generar una firma digital con la clave privada del emisor y unir ambos en un solo
        bloque de datos a enviar con un delimitador.
    """
    # Cifrado
    cifrador = PKCS1_OAEP.new(pub_receptor)         # Crear un objeto de cifrado con la clave publica del receptor
    mensaje_cifrado = cifrador.encrypt(mensaje)     # Cifrar los datos a enviar

    log("cifrar_mensaje", f"Mensaje original: {mensaje.decode()}")
    log("cifrar_mensaje", f"Mensaje cifrado de tamaño: {len(mensaje_cifrado)} bytes")

    # Huella Digital
    hash = SHA256.new(mensaje_cifrado)              # Crear un hash del mensaje
    firmador = pkcs1_15.new(priv_emisor)            # Crear un objeto de firma con la clave privada del emisor
    firma = firmador.sign(hash)                     # Firmar el hash del mensaje

    log("cifrar_mensaje", f"Hash calculado: {hash.hexdigest()}")
    log("cifrar_mensaje", f"Firma generada de tamaño: {len(firma)} bytes")

    # Informacion y Prueba de Autenticidad
    data = mensaje_cifrado + DELIMITADOR + firma    # Unir el mensaje y la firma en los datos a enviar

    log("cifrar_mensaje", f"Datos a enviar de tamaño: {len(data)} bytes")
    return data

def descifrar_mensaje(data: bytes, priv_receptor: RSA.RsaKey, pub_emisor: RSA.RsaKey) -> bytes | None:
    """
    Nombre funcion: descifrar_mensaje
    Parametros:
        - data: Informacion que se recibio en bytes
        - priv_receptor: Objeto de Clave privada RSA del receptor
        - pub_emisor: Objeto de Clave publica RSA del emisor
    Descripcion:
        Funcion que se encarga de separar el mensaje cifrado de la firma digital,
        verificar la firma con la clave publica del emisor y si es correcta,
        descifrar el mensaje utilizando la clave privada del receptor.
        Si la firma no es correcta o el mensaje no se puede descifrar,
        se asume que el mensaje ha sido saboteado y se devuelve None
    """
    log("descifrar_mensaje", f"Datos recibidos de tamaño: {len(data)} bytes")
    # Informacion y Prueba de Autenticidad
    mensaje_cifrado, firma = data.split(DELIMITADOR)# Separar el mensaje de la firma en los datos recibidos
    log("descifrar_mensaje", f"Mensaje cifrado recibido de tamaño: {len(mensaje_cifrado)} bytes")
    log("descifrar_mensaje", f"Firma recibida de tamaño: {len(firma)} bytes")
    try:
        # Huella Digital
        hash = SHA256.new(mensaje_cifrado)          # Crear un hash del mensaje
        firmador = pkcs1_15.new(pub_emisor)         # Crear un objeto de firma con la clave publica del emisor
        log("descifrar_mensaje", f"Hash calculado: {hash.hexdigest()}")
        log("descifrar_mensaje", "Verificando la firma con la clave publica del emisor")
        firmador.verify(hash, firma)                # Verificar la firma
    except (ValueError):
       # Error en la Huella Digital
       log("descifrar_mensaje", "¡¡¡SABOTAJE DETECTADO!!!")
       log("descifrar_mensaje", "El mensaje esta incompleto o no es autentico")
       return None

    try:
        # Descifrado
        cifrador = PKCS1_OAEP.new(priv_receptor)    # Crear un objeto de cifrado con la clave privada del receptor
        log("descifrar_mensaje", "Descifrando el mensaje con la clave privada del receptor")
        mensaje = cifrador.decrypt(mensaje_cifrado) # Descifrar los datos recibidos
    except (ValueError, TypeError):
        # Falla en cifrado
        log("descifrar_mensaje", "¡¡¡SABOTAJE DETECTADO!!!")
        log("descifrar_mensaje", "El mensaje esta incompleto o la clave utilizada no es correcta")
        return None
    log("descifrar_mensaje", f"Mensaje descifrado: {mensaje.decode()}")
    return mensaje

def generar_par() -> tuple[RSA.RsaKey, RSA.RsaKey]:
    """
    Nombre funcion: generar_par
    Parametros: Ninguno
    Descripcion:
        Funcion que se encarga de generar un par de claves RSA (publica y privada).
    """
    key = RSA.generate(2048)
    priv = key
    pub = key.publickey()
    return pub, priv

if __name__ == "__main__":
    # Definicion de los nombres
    A = "Aaron"
    B = "Brandon"
    C = "Carlos"
    mensajeA = f"El espia es {C}"
    mensajeB = "Nos estan saboteando, no podemos confiar en nadie"
    mensajeC = f"El espia es {A}"

    # Claves publicas y privadas
    pubA, privA = generar_par()
    pubB, privB = generar_par()
    pubC, privC = generar_par()

    # Cifrado del mensaje de A para B
    log(A, f"Voy a mandar un mensaje a {B}")
    log(A, f"mensaje: {mensajeA}")
    tabs += 1
    cifrado = cifrar_mensaje(
        mensaje=mensajeA.encode(),
        priv_emisor=privA,
        pub_receptor=pubB
    )
    tabs -= 1
    log(A, f"Enviando mensaje cifrado a {B}")

    # Descifrado del mensaje por parte de B
    log(B, f"Recibi un mensaje de {A}")
    tabs += 1
    descifrado = descifrar_mensaje(
        data=cifrado,
        priv_receptor=privB,
        pub_emisor=pubA
    )
    tabs -= 1
    if descifrado is not None:
        log(B, f"El mensaje es: {descifrado.decode()}")
    else:
        log(B, "No se pudo descifrar el mensaje o no es autentico")
        log(B, "Nos estan saboteando")

    # Ataque de C haciendose pasar por A
    log(C, f"Voy a mandar un mensaje al {B} haciendome pasar por {A}")
    log(C, f"mensaje: {mensajeC}")
    tabs += 1
    cifrado_falso = cifrar_mensaje(
        mensaje=mensajeC.encode(),
        priv_emisor=privC,
        pub_receptor=pubB
    )
    tabs -= 1
    log(C, f"Enviando mensaje cifrado falso a {B}")

    # Descifrado del mensaje por parte de B
    log(B, f"Recibi un mensaje de {A}")
    tabs += 1
    descifrado_falso = descifrar_mensaje(
        data=cifrado_falso,
        priv_receptor=privB,
        pub_emisor=pubA
    )
    tabs -= 1
    if descifrado_falso is not None:
        log(B, f"El mensaje es: {descifrado_falso.decode()}")
    else:
        log(B, "No se pudo descifrar el mensaje o no es autentico")
        log(B, "Nos estan saboteando")

    # Sabotaje de C modificando el mensaje de B para A
    log(B, f"Voy a mandar un mensaje a {A}")
    log(B, f"mensaje: {mensajeB}")
    tabs += 1
    cifrado_b = cifrar_mensaje(
        mensaje=mensajeB.encode(),
        priv_emisor=privB,
        pub_receptor=pubA
    )
    tabs -= 1
    log(B, f"Enviando mensaje cifrado a {A}")

    # C intercepta el mensaje y lo modifica
    log(C, f"Intercepte el mensaje de {B}")
    tabs += 1
    mensaje_cifrado_C = cifrado_falso.split(DELIMITADOR)[0]
    firma_B = cifrado_b.split(DELIMITADOR)[1]
    cifrado_modificado = mensaje_cifrado_C + DELIMITADOR + firma_B
    log(C, "Modificando mensaje B + DELIMITADOR + firma B -> mensaje C + DELIMITADOR + firma B")
    tabs -= 1
    log(C, f"Enviando mensaje cifrado modificado a {A}")

    # A recibe el mensaje modificado
    log(A, f"Recibi un mensaje de {B}")
    tabs += 1
    descifrado_modificado = descifrar_mensaje(
        data=cifrado_modificado,
        priv_receptor=privA,
        pub_emisor=pubB
    )
    tabs -= 1
    if descifrado_modificado is not None:
        log(A, f"El mensaje es: {descifrado_modificado.decode()}")
    else:
        log(A, "No se pudo descifrar el mensaje o no es autentico")
        log(A, "Nos estan saboteando")
