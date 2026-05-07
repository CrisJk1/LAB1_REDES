from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
import random

PRIME = 2**256 - 189

def generar_coeficientes():
    a1 = 0
    a2 = 0
    while(a1 == a2):
        a1 = random.randint(1, PRIME - 1)
        a2 = random.randint(1, PRIME - 1)
    return (a1, a2)

def evaluar_polinomio(secreto, x, a1, a2):
    fx = (secreto + a1*x + a2*x*x) % PRIME
    return (x, fx)

def generar_secreto():
    secreto_hex = get_random_bytes(32)
    secreto = int.from_bytes(secreto_hex, "big")
    a1, a2 = generar_coeficientes()
    return (secreto, secreto_hex, a1, a2)

def li(i, puntos):
    xi = puntos[i][0]
    mult = 1

    for j in range(len(puntos)):
        xj = puntos[j][0]
        if(xi !=xj):mult = mult * ((-xj % PRIME) * pow((xi - xj) % PRIME, -1, PRIME))
    
    return mult % PRIME

def interpolacion_lagrange(puntos):
    secreto = 0
    for i in range(len(puntos)):
        yi = puntos[i][1]
        Li = li(i, puntos)
        secreto = (secreto + yi * Li) % PRIME
    return secreto

def guardar_claves(secreto_hex, f1, f2, f3, f4):
    with open("CODIGO/keys/secreto.txt", "w") as f:
        f.write(f"Llave: {secreto_hex.hex()}\n")
    
    with open("CODIGO/keys/partes.txt", "w") as f:
        f.write(f"Parte 1: {f1}\n")
        f.write(f"Parte 2: {f2}\n")
        f.write(f"Parte 3: {f3}\n")
        f.write(f"Parte 4: {f4}\n")


def simulacion(f1, f2, f3, f4, secreto):
    # Exito con 4 partes:
    print(f"f1+f2+f3+f4: {secreto == interpolacion_lagrange([f1, f2, f3, f4])}")

    # Exito con 3 partes:
    print(f"f1+f2+f3: {secreto == interpolacion_lagrange([f1, f2, f3])}")
    print(f"f1+f3+f2: {secreto == interpolacion_lagrange([f1, f3, f2])}")
    print(f"f2+f1+f3: {secreto == interpolacion_lagrange([f2, f1, f3])}")
    print(f"f2+f3+f1: {secreto == interpolacion_lagrange([f2, f3, f1])}")
    print(f"f3+f1+f2: {secreto == interpolacion_lagrange([f3, f1, f2])}")
    print(f"f3+f2+f1: {secreto == interpolacion_lagrange([f3, f2, f1])}")
    print(f"f1+f2+f4: {secreto == interpolacion_lagrange([f1, f2, f4])}")
    print(f"f1+f4+f2: {secreto == interpolacion_lagrange([f1, f4, f2])}")
    print(f"f2+f1+f4: {secreto == interpolacion_lagrange([f2, f1, f4])}")
    print(f"f2+f4+f1: {secreto == interpolacion_lagrange([f2, f4, f1])}")
    print(f"f4+f1+f2: {secreto == interpolacion_lagrange([f4, f1, f2])}")
    print(f"f4+f2+f1: {secreto == interpolacion_lagrange([f4, f2, f1])}")
    print(f"f1+f3+f4: {secreto == interpolacion_lagrange([f1, f3, f4])}")
    print(f"f1+f4+f3: {secreto == interpolacion_lagrange([f1, f4, f3])}")
    print(f"f3+f1+f4: {secreto == interpolacion_lagrange([f3, f1, f4])}")
    print(f"f3+f4+f1: {secreto == interpolacion_lagrange([f3, f4, f1])}")
    print(f"f4+f1+f3: {secreto == interpolacion_lagrange([f4, f1, f3])}")
    print(f"f4+f3+f1: {secreto == interpolacion_lagrange([f4, f3, f1])}")
    print(f"f2+f3+f4: {secreto == interpolacion_lagrange([f2, f3, f4])}")
    print(f"f2+f4+f3: {secreto == interpolacion_lagrange([f2, f4, f3])}")
    print(f"f3+f2+f4: {secreto == interpolacion_lagrange([f3, f2, f4])}")
    print(f"f3+f4+f2: {secreto == interpolacion_lagrange([f3, f4, f2])}")
    print(f"f4+f2+f3: {secreto == interpolacion_lagrange([f4, f2, f3])}")
    print(f"f4+f3+f2: {secreto == interpolacion_lagrange([f4, f3, f2])}")

    # Fallo con 2 partes:
    print(f"f1+f2: {secreto == interpolacion_lagrange([f1, f2])}")
    print(f"f2+f1: {secreto == interpolacion_lagrange([f2, f1])}")
    print(f"f1+f3: {secreto == interpolacion_lagrange([f1, f3])}")
    print(f"f3+f1: {secreto == interpolacion_lagrange([f3, f1])}")
    print(f"f1+f4: {secreto == interpolacion_lagrange([f1, f4])}")
    print(f"f4+f1: {secreto == interpolacion_lagrange([f4, f1])}")
    print(f"f2+f3: {secreto == interpolacion_lagrange([f2, f3])}")
    print(f"f3+f2: {secreto == interpolacion_lagrange([f3, f2])}")
    print(f"f2+f4: {secreto == interpolacion_lagrange([f2, f4])}")
    print(f"f4+f2: {secreto == interpolacion_lagrange([f4, f2])}")
    print(f"f3+f4: {secreto == interpolacion_lagrange([f3, f4])}")
    print(f"f4+f3: {secreto == interpolacion_lagrange([f4, f3])}")
    
    # Fallo con 1 parte
    print(f"f1: {secreto == interpolacion_lagrange([f1])}")
    print(f"f2: {secreto == interpolacion_lagrange([f2])}")
    print(f"f3: {secreto == interpolacion_lagrange([f3])}")
    print(f"f4: {secreto == interpolacion_lagrange([f4])}")

if __name__ == "__main__":
    secreto, secreto_hex, a1, a2 = generar_secreto()
    f1 = evaluar_polinomio(secreto, 1, a1, a2)
    f2 = evaluar_polinomio(secreto, 2, a1, a2)
    f3 = evaluar_polinomio(secreto, 3, a1, a2)
    f4 = evaluar_polinomio(secreto, 4, a1, a2)
    guardar_claves(secreto_hex, f1, f2, f3, f4)
    print(f"Secreto original:     {secreto}")
    simulacion(f1, f2, f3, f4, secreto)
