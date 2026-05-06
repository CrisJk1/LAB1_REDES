from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

AES_BLOCK_SIZE_BYTES = 16
AES128_KEY_SIZE_BYTES = 16
BASE_DIR = Path(__file__).resolve().parent
REPO_DIR = BASE_DIR.parent
DEFAULT_KEYS_DIR = BASE_DIR / "keys"
DEFAULT_DATA_DIR = BASE_DIR / "data"
DEFAULT_OUTPUT_DIR = BASE_DIR / "outputs/fase2"

class Phase2Error(Exception):
    """
    Nombre funcion: Phase2Error
    Parametros: message (str), descripcion del error operativo.
    Descripcion: Excepcion propia para reportar fallas controladas durante la fase II.
    """


def escribir_bytes(path: Path, data: bytes) -> None:
    """
    Nombre funcion: escribir_bytes
    Parametros: path (Path), ruta de salida; data (bytes), contenido a escribir.
    Descripcion: Escribe bytes en un archivo creando directorios padres si corresponde.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def escribir_json(path: Path, data: Dict[str, Any]) -> None:
    """
    Nombre funcion: escribir_json
    Parametros: path (Path), ruta de salida; data (dict), informacion serializable.
    Descripcion: Escribe metadata JSON indentada para facilitar revision en el informe.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def cifrar_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Nombre funcion: cifrar_aes_cbc
    Parametros: plaintext (bytes), datos originales; key (bytes), clave AES-128; iv (bytes), vector inicial.
    Descripcion: Cifra datos con AES-128-CBC usando PKCS7 para ajustar el largo a bloques.
    """
    if len(key) != AES128_KEY_SIZE_BYTES:
        raise Phase2Error("AES-128 requiere una clave de 16 bytes")
    if len(iv) != AES_BLOCK_SIZE_BYTES:
        raise Phase2Error("AES-CBC requiere un IV de 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(AES_BLOCK_SIZE_BYTES * 8).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def descifrar_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Nombre funcion: descifrar_aes_cbc
    Parametros: ciphertext (bytes), datos cifrados; key (bytes), clave AES-128; iv (bytes), vector inicial.
    Descripcion: Descifra datos con AES-128-CBC y remueve padding PKCS7.
    """
    if len(key) != AES128_KEY_SIZE_BYTES:
        raise Phase2Error("AES-128 requiere una clave de 16 bytes")
    if len(iv) != AES_BLOCK_SIZE_BYTES:
        raise Phase2Error("AES-CBC requiere un IV de 16 bytes")
    if len(ciphertext) % AES_BLOCK_SIZE_BYTES != 0:
        raise Phase2Error("El ciphertext AES-CBC debe tener largo multiplo de 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(AES_BLOCK_SIZE_BYTES * 8).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


def cifrar_hibrido(input_path: Path, recipient_public_key_path: Path, recipient: str, output_dir: Path) -> Dict[str, Any]:
    """
    Nombre funcion: cifrar_hibrido
    Parametros: input_path (Path), archivo original; recipient_public_key_path (Path), llave publica RSA; recipient (str), id del destinatario; output_dir (Path), carpeta de salida.
    Descripcion: Cifra un archivo con AES-128-CBC y cifra la clave AES con RSA-OAEP-SHA256.
    """
    plaintext = input_path.read_bytes()
    public_key = cast(
        rsa.RSAPublicKey,
        serialization.load_pem_public_key(recipient_public_key_path.read_bytes()),
    )

    session_key = os.urandom(AES128_KEY_SIZE_BYTES)
    iv = os.urandom(AES_BLOCK_SIZE_BYTES)
    ciphertext = cifrar_aes_cbc(plaintext, session_key, iv)
    encrypted_session_key = public_key.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    ciphertext_path = output_dir / "ciphertext.bin"
    encrypted_key_path = output_dir / "encrypted_session_key.bin"
    iv_path = output_dir / "iv.bin"
    decrypted_path = output_dir / "decrypted_silo_manifesto.txt"
    metadata_file_path = output_dir / "metadata.json"

    escribir_bytes(ciphertext_path, ciphertext)
    escribir_bytes(encrypted_key_path, encrypted_session_key)
    escribir_bytes(iv_path, iv)

    metadata: Dict[str, Any] = {
        "tipo": "cifrado_hibrido",
        "archivo_original": str(input_path.resolve().relative_to(REPO_DIR)),
        "archivo_cifrado": str(ciphertext_path.resolve().relative_to(REPO_DIR)),
        "archivo_descifrado": str(decrypted_path.resolve().relative_to(REPO_DIR)),
        "destinatario": recipient,
        "llave_publica_destinatario": str(recipient_public_key_path.resolve().relative_to(REPO_DIR)),
        "cifrado_simetrico": {
            "algoritmo": "AES",
            "tamano_clave_bits": 128,
            "modo": "CBC",
            "padding": "PKCS7",
            "iv_archivo": str(iv_path.resolve().relative_to(REPO_DIR)),
        },
        "cifrado_asimetrico": {
            "algoritmo": "RSA",
            "padding": "OAEP",
            "hash": "SHA-256",
            "clave_sesion_cifrada": str(encrypted_key_path.resolve().relative_to(REPO_DIR)),
        },
        "verificacion": {
            "sha256_original": hashlib.sha256(plaintext).hexdigest(),
            "sha256_descifrado": None,
            "coinciden": None,
        },
    }
    escribir_json(metadata_file_path, metadata)
    return metadata


def descifrar_hibrido(
    package_dir: Path,
    recipient_private_key_path: Path,
    output_path: Path,
    expected_hash: str,
) -> Dict[str, Any]:
    """
    Nombre funcion: descifrar_hibrido
    Parametros: package_dir (Path), carpeta con ciphertext/iv/key; recipient_private_key_path (Path), llave privada RSA; output_path (Path), archivo recuperado; expected_hash (str), hash esperado.
    Descripcion: Descifra la clave AES con RSA-OAEP y luego recupera el archivo con AES-128-CBC.
    """
    ciphertext = (package_dir / "ciphertext.bin").read_bytes()
    encrypted_session_key = (package_dir / "encrypted_session_key.bin").read_bytes()
    iv = (package_dir / "iv.bin").read_bytes()
    private_key = cast(
        rsa.RSAPrivateKey,
        serialization.load_pem_private_key(recipient_private_key_path.read_bytes(), password=None),
    )

    session_key = private_key.decrypt(
        encrypted_session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = descifrar_aes_cbc(ciphertext, session_key, iv)
    escribir_bytes(output_path, plaintext)

    recovered_hash = hashlib.sha256(plaintext).hexdigest()
    integrity_ok = expected_hash == recovered_hash

    verification = {
        "sha256_original": expected_hash,
        "sha256_descifrado": recovered_hash,
        "coinciden": integrity_ok,
    }

    if not integrity_ok:
        raise Phase2Error("El hash SHA-256 recuperado no coincide con el original")
    return verification


def obtener_offset_bmp(bmp_data: bytes) -> int:
    """
    Nombre funcion: obtener_offset_bmp
    Parametros: bmp_data (bytes), contenido completo de una imagen BMP.
    Descripcion: Lee el offset donde comienzan los pixeles de un BMP.
    """
    if len(bmp_data) < 54:
        raise Phase2Error("El archivo BMP es demasiado pequeno")
    if bmp_data[:2] != b"BM":
        raise Phase2Error("El archivo no tiene firma BMP 'BM'")

    pixel_offset = struct.unpack_from("<I", bmp_data, 10)[0]
    if pixel_offset <= 0 or pixel_offset >= len(bmp_data):
        raise Phase2Error("Offset de pixeles invalido en BMP")
    return pixel_offset


def cifrar_bloques(data: bytes, key: bytes, mode_name: str, iv: Optional[bytes] = None) -> bytes:
    """
    Nombre funcion: cifrar_bloques
    Parametros: data (bytes), datos a cifrar; key (bytes), clave AES; mode_name (str), ECB o CBC; iv (bytes|None), IV para CBC.
    Descripcion: Cifra solo bloques completos sin padding y conserva la cola sin cifrar para no romper el BMP.
    """
    if len(key) != AES128_KEY_SIZE_BYTES:
        raise Phase2Error("AES-128 requiere una clave de 16 bytes")

    full_len = (len(data) // AES_BLOCK_SIZE_BYTES) * AES_BLOCK_SIZE_BYTES
    full_blocks = data[:full_len]
    tail = data[full_len:]

    if mode_name == "ECB":
        mode = modes.ECB()
    elif mode_name == "CBC":
        if iv is None or len(iv) != AES_BLOCK_SIZE_BYTES:
            raise Phase2Error("CBC requiere IV de 16 bytes")
        mode = modes.CBC(iv)
    else:
        raise Phase2Error("Modo no soportado para BMP; use ECB o CBC")

    cipher = Cipher(algorithms.AES(key), mode)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(full_blocks) + encryptor.finalize()
    return encrypted + tail


def cifrar_pixeles_bmp(bmp_path: Path, output_path: Path, key: bytes, mode_name: str, iv: Optional[bytes] = None) -> None:
    """
    Nombre funcion: cifrar_pixeles_bmp
    Parametros: bmp_path (Path), imagen BMP original; output_path (Path), imagen BMP cifrada; key (bytes), clave AES; mode_name (str), ECB o CBC; iv (bytes|None), IV para CBC.
    Descripcion: Preserva el encabezado BMP y cifra los pixeles para comparar fuga visual ECB vs CBC.
    """
    bmp_data = bmp_path.read_bytes()
    pixel_offset = obtener_offset_bmp(bmp_data)

    header = bmp_data[:pixel_offset]
    pixels = bmp_data[pixel_offset:]
    encrypted_pixels = cifrar_bloques(pixels, key, mode_name, iv)
    output_data = header + encrypted_pixels
    escribir_bytes(output_path, output_data)


def comparar_ecb_cbc(bmp_path: Path, output_dir: Path) -> Dict[str, Any]:
    """
    Nombre funcion: comparar_ecb_cbc
    Parametros: bmp_path (Path), BMP original; output_dir (Path), carpeta de salida;
    Descripcion: Ejecuta la comparacion ECB vs CBC y deja BMPs + metadata como evidencia.
    """
    if not bmp_path.exists():
        raise Phase2Error("El archivo BMP no existe")

    key = os.urandom(AES128_KEY_SIZE_BYTES)
    cbc_iv = os.urandom(AES_BLOCK_SIZE_BYTES)
    output_dir.mkdir(parents=True, exist_ok=True)

    ecb_output = output_dir / "silo_ecb.bmp"
    cbc_output = output_dir / "silo_cbc.bmp"
    cbc_iv_path = output_dir / "cbc_iv.bin"

    escribir_bytes(cbc_iv_path, cbc_iv)
    cifrar_pixeles_bmp(bmp_path, ecb_output, key, "ECB")
    cifrar_pixeles_bmp(bmp_path, cbc_output, key, "CBC", cbc_iv)

    metadata: Dict[str, Any] = {
        "tipo": "comparacion_ecb_cbc",
        "imagen_original": str(bmp_path.resolve().relative_to(REPO_DIR)),
        "imagen_ecb": str(ecb_output.resolve().relative_to(REPO_DIR)),
        "imagen_cbc": str(cbc_output.resolve().relative_to(REPO_DIR)),
        "algoritmo": "AES",
        "tamano_clave_bits": 128,
        "modo_ecb": {
            "modo": "ECB",
            "iv": "no_aplica",
        },
        "modo_cbc": {
            "modo": "CBC",
            "iv_archivo": str(cbc_iv_path.resolve().relative_to(REPO_DIR)),
        },
    }
    escribir_json(output_dir / "metadata.json", metadata)
    return metadata


def pedir_par_llaves(keys_dir: Path) -> Tuple[str, Path, Path]:
    """
    Nombre funcion: pedir_par_llaves
    Parametros: keys_dir (Path), carpeta de llaves.
    Descripcion: Solicita nombres hasta encontrar el par de llaves generado por fase I.
    """
    while True:
        try:
            recipient = input("Nombre de la key: ").strip()
        except EOFError as exc:
            raise Phase2Error("Debe indicar el nombre de la key por terminal") from exc

        if not recipient:
            print("[AVISO] El nombre de la key no puede estar vacio", file=sys.stderr)
            continue

        public_key_path = keys_dir / recipient / f"{recipient}_pub.pem"
        private_key_path = keys_dir / recipient / f"{recipient}_priv.pem"
        if public_key_path.exists() and private_key_path.exists():
            print(f"[OK] Llaves encontradas para: {recipient}")
            return recipient, public_key_path, private_key_path

        print("[AVISO] No existe una llave con ese nombre", file=sys.stderr)


def ejecutar_fase2(
    recipient: str,
    public_key_path: Path,
    private_key_path: Path,
    data_dir: Path,
    output_dir: Path,
) -> None:
    """
    Nombre funcion: ejecutar_fase2
    Parametros: recipient (str), miembro receptor; public_key_path (Path), llave publica; private_key_path (Path), llave privada; data_dir (Path), datos de entrada; output_dir (Path), salida.
    Descripcion: Ejecuta la fase completa: cifra/descifra el manifiesto existente y genera ECB vs CBC.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    plaintext_path = data_dir / "silo_manifesto.txt"
    bmp_path = data_dir / "silo_circuito.bmp"

    print(f"[INFO] Archivo a cifrar: {plaintext_path}")

    hybrid_dir = output_dir / "hybrid"
    print("[INFO] Cifrando archivo con AES-CBC y protegiendo la clave con RSA-OAEP")
    hybrid_metadata = cifrar_hibrido(plaintext_path, public_key_path, recipient, hybrid_dir)

    decrypted_path = hybrid_dir / "decrypted_silo_manifesto.txt"
    print("[INFO] Descifrando archivo y verificando integridad SHA-256")
    verification = descifrar_hibrido(
        hybrid_dir,
        private_key_path,
        decrypted_path,
        hybrid_metadata["verificacion"]["sha256_original"],
    )
    hybrid_metadata["verificacion"] = verification
    escribir_json(hybrid_dir / "metadata.json", hybrid_metadata)

    print(f"[OK] Verificacion de integridad: {verification['coinciden']}")
    print(f"[INFO] Generando comparacion ECB vs CBC con imagen BMP: {bmp_path}")
    comparar_ecb_cbc(bmp_path, output_dir / "bmp_demo")
    print("[OK] Comparacion ECB vs CBC generada")


def main() -> int:
    """
    Nombre funcion: main
    Parametros: ninguno.
    Descripcion: Punto de entrada CLI; ejecuta la fase II completa y reporta errores de forma legible.
    """
    try:
        recipient, public_key_path, private_key_path = pedir_par_llaves(DEFAULT_KEYS_DIR)
        ejecutar_fase2(
            recipient,
            public_key_path,
            private_key_path,
            DEFAULT_DATA_DIR,
            DEFAULT_OUTPUT_DIR,
        )
        return 0
    except Phase2Error as exc:
        print(f"[ERROR FASE II] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[ERROR INESPERADO] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
