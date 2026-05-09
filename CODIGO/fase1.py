import os
import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

class DeterministicRNG:
    """
    ■ Clase: DeterministicRNG
    ■ Descripción: Simula un generador de números aleatorios (PRNG) que produce
      una secuencia determinista de bytes a partir de una semilla fija.
    """
    def __init__(self, seed):
        """
        ■ Parámetros: [seed: bytes]
        ■ Descripción: Inicializa el generador con la Strong Key y un contador en cero.
        """        
        self.seed = seed
        self.counter = 0

    def __call__(self, n):
        """
        ■ Nombre función: __call__
        ■ Parámetros: [n: int]
        ■ Descripción: Genera 'n' bytes deterministas. Es la función que RSA.generate
          invoca para obtener la "entropía" necesaria para las llaves.
        """
        result = b""
        while len(result) < n:
            # Estiramos la semilla usando hashing para obtener 'n' bytes
            hash_input = self.seed + self.counter.to_bytes(4, 'big')
            result += SHA256.new(hash_input).digest()
            self.counter += 1
        return result[:n]

def obtener_identidad(nombre, rol):
    """
    ■ Nombre función: obtener_identidad
    ■ Parámetros: [nombre: str, rol: str]
    ■ Descripción: Implementa la Fase 1 completa. Maneja la creación/carga 
      del SALT, deriva la Strong Key con PBKDF2 y genera el par RSA.
    """
    # Generamos una ruta específica para el miembro (ej: CODIGO/keys/Cristobal)
    folder_user = os.path.join("CODIGO", "keys", nombre)
    os.makedirs(folder_user, exist_ok=True)
    
    # El salt se guarda dentro de la carpeta del usuario
    salt_path = os.path.join(folder_user, f"{nombre}_salt.bin")
    
    # Tarea 2: Inyección de SALT (Carga o Generación)
    if os.path.exists(salt_path):
        print(f"[*] SALT existente encontrado para {nombre}. Cargando...")
        with open(salt_path, "rb") as f:
            salt = f.read()
    else:
        print(f"[*] Generando nuevo SALT aleatorio para {nombre}...")
        salt = get_random_bytes(16)
        with open(salt_path, "wb") as f:
            f.write(salt)

    # Tarea 1: Strong Key con PBKDF2
    passphrase = f"{nombre}{rol}".encode('utf-8')
    strong_key = PBKDF2(passphrase, salt, dkLen=32, count=600000, hmac_hash_module=SHA256)
    
    # Tarea 3: Generación Par de Llaves RSA-2048
    print(f"[*] Derivando llaves RSA de 2048 bits...")
    rng = DeterministicRNG(strong_key)
    key_pair = RSA.generate(2048, randfunc=rng)
    
    return key_pair, salt

def guardar_llaves(key_pair, nombre):
    """
    ■ Nombre función: guardar_llaves
    ■ Parámetros: [key_pair: RsaKey, nombre: str]
    ■ Descripción: Guarda las llaves RSA en formato PEM dentro de la carpeta del miembro.
    """
    # Apuntamos a la carpeta específica del usuario
    folder_user = os.path.join("CODIGO", "keys", nombre)
    
    path_priv = os.path.join(folder_user, f"{nombre}_priv.pem")
    path_pub = os.path.join(folder_user, f"{nombre}_pub.pem")
    
    with open(path_priv, "wb") as f:
        f.write(key_pair.export_key())
    with open(path_pub, "wb") as f:
        f.write(key_pair.public_key().export_key())
    
    print(f"[+] Credenciales guardadas en: {folder_user}/")

if __name__ == "__main__":
    """
    ■ Bloque: Punto de Entrada Principal
    ■ Descripción: Orquesta el flujo de la Fase 1 permitiendo el ingreso 
      múltiple de miembros.
    """
    print("--- PROTOCOLO OMEGA: IDENTIDAD CRIPTOGRÁFICA ---")
    
    while True:
        # 1. Captura de datos
        u_nombre = input("\nIngrese Nombre del miembro (o 'salir' para terminar): ").strip().replace(" ", "_")
        
        # Opción de salida
        if u_nombre.lower() == 'salir':
            print("[!] Finalizando registro de identidades...")
            break
            
        u_rol = input(f"Ingrese ROL de {u_nombre}: ").strip()

        # 2. Validación básica
        if not u_nombre or not u_rol:
            print("[!] Error: El nombre y el ROL no pueden estar vacíos. Reintente.")
            continue

        # 3. Ejecución del protocolo
        try:
            llaves, salt_utilizado = obtener_identidad(u_nombre, u_rol)
            guardar_llaves(llaves, u_nombre)
            print(f"[V] Identidad de {u_nombre} generada con éxito.")
        except Exception as e:
            print(f"[X] Error inesperado procesando a {u_nombre}: {e}")

        # 4. Preguntar si desea continuar
        continuar = input("\n¿Desea ingresar a otro miembro? (s/n): ").strip().lower()
        if continuar != 's':
            print("[!] Protocolo finalizado. Cerrando terminal.")
            break

    print("\n--- PROCESO COMPLETADO ---")