from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

DELIMITADOR = b"<-x->"
mensajes = []
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

def cifrar_mensaje(mensaje: bytes, priv_emisor: RSA.RsaKey, simetrica: bytes) -> bytes:
    """
    Nombre funcion: cifrar_mensaje
    Parametros:
        - mensaje: Mensaje a cifrar
        - priv_emisor: Clave privada del emisor del mensaje
        - simetrica: Clave simetrica para cifrar el mensaje
    Descripcion:
        Funcion que se encarga de cifrar un mensaje utilizando AES con la clave simetrica
        y luego firmar el mensaje cifrado utilizando la clave privada del emisor.
        Se retornan nonce, tag, mensaje cifrado y firma unidos por un delimitador.
    """
    cifrador = AES.new(simetrica, AES.MODE_GCM)
    nonce = cifrador.nonce
    mensaje_cifrado, tag = cifrador.encrypt_and_digest(mensaje)

    hash = SHA256.new(mensaje_cifrado)
    firmador = pkcs1_15.new(priv_emisor)
    firma = firmador.sign(hash)

    data = DELIMITADOR.join([
        nonce,
        tag,
        mensaje_cifrado,
        firma
    ])

    return data

def descifrar_mensaje(data: bytes, pub_emisor: RSA.RsaKey, simetrica: bytes) -> tuple[bytes | None, str]:
    """
    Nombre funcion: descifrar_mensaje
    Parametros:
        - data: Datos a descifrar
        - pub_emisor: Clave publica del emisor del mensaje
        - simetrica: Clave simetrica para descifrar el mensaje
    Descripcion:
        Funcion que se encarga de descifrar un mensaje utilizando AES con la clave simetrica
        y luego verificar la firma utilizando la clave publica del emisor.
    """
    # Separar los datos
    nonce, tag, mensaje_cifrado, firma = data.split(DELIMITADOR)

    try:
        # Descifrar con simetrica y comprobar integridad
        cifrador = AES.new(simetrica, AES.MODE_GCM, nonce=nonce)
        mensaje = cifrador.decrypt_and_verify(mensaje_cifrado, tag)
    except (ValueError):
        log(SIS, "La clave es incorrecta")
        return None, "incorrecta"

    try:
        # Verificar autenticidad
        hash = SHA256.new(mensaje_cifrado)
        firmador = pkcs1_15.new(pub_emisor)
        firmador.verify(hash, firma)
    except (ValueError):
        log(SIS, "La firma no es valida o el mensaje fue modificado")
        return None, "invalido"

    return mensaje, "correcto"

def enviar_mensaje(mensaje: bytes, priv_emisor: RSA.RsaKey, simetrica: bytes):
    """
    Nombre funcion: enviar_mensaje
    Parametros:
        - mensaje: Mensaje a enviar
        - priv_emisor: Clave privada del emisor del mensaje
        - simetrica: Clave simetrica para cifrar el mensaje
    Descripcion:
        Funcion que se encarga de cifrar un mensaje y agregarlo a la lista de mensajes del consejo.
    """
    mensaje_cifrado = cifrar_mensaje(mensaje, priv_emisor, simetrica)
    mensajes.append(mensaje_cifrado)

def recibir_mensaje(pubs: dict[str, RSA.RsaKey], simetrica: bytes) -> tuple[bytes | None, str]:
    """
    Nombre funcion: recibir_mensaje
    Parametros:
        - pubs: Diccionario con las claves publicas de los usuarios del consejo
        - simetrica: Clave simetrica para descifrar el mensaje
    Descripcion:
        Funcion que se encarga de recibir un mensaje y verificar su autenticidad.
    """
    global tabs
    log(SIS, "Mensaje recibido")
    data = mensajes.pop()
    for usuario in pubs.keys():
        tabs += 1
        pub = pubs[usuario]
        log(SIS, f"Comprobando usuario ({usuario})")
        mensaje, error = descifrar_mensaje(data=data, pub_emisor=pub, simetrica=simetrica)
        tabs -= 1
        if mensaje is not None:
            log(SIS, "El mensaje proviene del consejo")
            return mensaje, usuario
        if error == "incorrecta":
            log(SIS, "La clave no es del consejo")
            return None, "ERROR"
    log(SIS, "El mensaje no proviene de ningun usuario del consejo o fue modificado")
    log(SIS, "SABOTAJE DETECTADO")
    return None, "ERROR"


if __name__ == '__main__':
    A = "consejo | Aaron"
    B = "consejo | Brandon"
    C = "traidor | Carlos"
    D = "externo | Daniel"
    SIS = "SISTEMA"

    simetricaConsejo = get_random_bytes(32)
    pubA, privA = generar_par()
    pubB, privB = generar_par()
    pubD, privD = generar_par()

    consejo = {
        A: pubA,
        B: pubB,
    }

    log(C, f"Le dare la clave simetrica del consejo a ({D}) para que mande mensajes falsos")
    log(SIS, f"El usuario ({C}) ha sido expulsado")
    mensajeD = f"Soy ({A}) deben mandar los codigos a http://no-secure-place.ru/codes"
    log(D, f"Voy a mandar un mensaje al consejo: '{mensajeD}'")
    enviar_mensaje(
        mensaje=mensajeD.encode(),
        priv_emisor=privD,
        simetrica=simetricaConsejo
    )

    mensajeD2, emisorD2 = recibir_mensaje(consejo, simetricaConsejo)

    log(A, f"Avisare que ({C}) nos traiciono")
    mensajeA = f"({C}) compartio la clave simetrica"
    log(A, f"mensaje: {mensajeA}")
    enviar_mensaje(
        mensaje=mensajeA.encode(),
        priv_emisor=privA,
        simetrica=simetricaConsejo
    )

    mensajeA2, emisorA2 = recibir_mensaje(consejo, simetricaConsejo)
    log(B, f"Recibi el mensaje de ({emisorA2})")

    log(B, "Voy a responder al mensaje")
    mensajeB = "Debemos cambiar la clave simetrica del consejo"
    log(B, f"mensaje: '({mensajeB})'")
    enviar_mensaje(
        mensaje=mensajeA.encode(),
        priv_emisor=privA,
        simetrica=simetricaConsejo
    )

    log(C, "Intercepte el mensaje, voy a modificarlo manteniendo la firma original")
    mensajeB_modificado = "Debemos mantener la clave simetrica del consejo"
    log(C, f"mensaje modificado: '{mensajeB_modificado}'")
    mensaje_interceptado = mensajes.pop()
    # Obtener la firma original del mensaje
    _, _, _, firma_original = mensaje_interceptado.split(DELIMITADOR)
    # Cifrar un nuevo mensaje
    nonce, tag, mensaje_cifrado_modificado, _ = cifrar_mensaje(mensajeB_modificado.encode(), privD, simetricaConsejo).split(DELIMITADOR)
    # Nuevo mensaje cifrado + Firma original del interceptado
    mensaje_alterado_con_firma = DELIMITADOR.join([nonce, tag, mensaje_cifrado_modificado, firma_original])
    mensajes.append(mensaje_alterado_con_firma)

    mensajeB2, emisorB2 = recibir_mensaje(consejo, simetricaConsejo)
