from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

DELIMITADOR = b"<<DELIMITADOR>>"

def cifrar_mensaje(mensaje: bytes, priv_emisor: RSA.RsaKey, pub_receptor: RSA.RsaKey) -> bytes:
    """
    Nombre funcion: cifrar_mensaje
    Parametros:
        - mensaje: Informacion que se quiere enviar en bytes
        - priv_emisor: Objeto de Clave privada RSA del emisor
        - pub_receptor: Objeto de Clave publica RSA del receptor
    Descripcion:
        Esta funcion devuelve en bytes el mensaje junto a una firma unidos por un delimitador y
        cifrados con la clave publica del receptor. La firma es simplemente el hash SHA256 del
        mensaje cifrado con la clave privada del emisor.
    """
    # Huella Digital
    hash = SHA256.new(mensaje)                      # Crear un hash del mensaje
    firmador = pkcs1_15.new(priv_emisor)            # Crear un objeto de firma con la clave privada del emisor
    firma = firmador.sign(hash)                     # Firmar el hash del mensaje

    # Informacion y Prueba de Autenticidad
    data = mensaje + DELIMITADOR + firma            # Unir el mensaje y la firma en los datos a enviar

    # Cifrado
    cifrador = PKCS1_OAEP.new(pub_receptor)         # Crear un objeto de cifrado con la clave publica del receptor
    mensaje_cifrado = cifrador.encrypt(data)        # Cifrar los datos a enviar

    return mensaje_cifrado

def descifrar_mensaje(mensaje_cifrado: bytes, priv_receptor: RSA.RsaKey, pub_emisor: RSA.RsaKey) -> bytes | None:
    """
    Nombre funcion: descifrar_mensaje
    Parametros:
        - mensaje_cifrado: Informacion que se recibio en bytes
        - priv_receptor: Objeto de Clave privada RSA del receptor
        - pub_emisor: Objeto de Clave publica RSA del emisor
    Descripcion:
        Esta funcion devuelve en bytes el mensaje descifrado, solo si esta completo y es autentico. Se comprueba la
        integridad y la autenticidad al mismo tiempo comparando el hash recibido (firmado) con el hash calculado.
    """
    try:
        # Descifrado
        cifrador = PKCS1_OAEP.new(priv_receptor)    # Crear un objeto de cifrado con la clave privada del receptor
        data = cifrador.decrypt(mensaje_cifrado)    # Descifrar los datos recibidos
    except (ValueError, TypeError):
        # Falla en cifrado
        print("descifrar_mensaje: El mensaje esta incompleto o la clave utilizada no es correcta")
        return None

    # Informacion y Prueba de Autenticidad
    mensaje, firma = data.split(DELIMITADOR)        # Separar el mensaje de la firma en los datos recibidos

    try:
        # Huella Digital
        hash = SHA256.new(mensaje)                  # Crear un hash del mensaje
        firmador = pkcs1_15.new(pub_emisor)         # Crear un objeto de firma con la clave publica del emisor
        firmador.verify(hash, firma)                # Verificar la firma
    except (ValueError):
       # Error en la Huella Digital
       print("descifrar_mensaje: El mensaje esta incompleto o no es autentico")
       return None

    return mensaje


if __name__ == "__main__":
    print("Fase 3")
