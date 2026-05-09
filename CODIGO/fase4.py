import secrets
from itertools import combinations, permutations

PRIME = 2**521 - 1

"""
Nombre funcion: generar_coeficientes
Parametros:
    - Ninguno
Descripcion:
    Se encarga de generar los 2 coeficientes para el polinomio que calcula las partes
"""
def generar_coeficientes():
    a1 = secrets.randbelow(PRIME - 1) + 1
    a2 = secrets.randbelow(PRIME - 1) + 1
    return (a1, a2)

"""
Nombre funcion: evaluar_polinomio
Parametros:
    - secreto: entero que representa el secreto
    - x: entero que representa el punto a evaluar
    - a1: entero que representa el coeficiente de grado 1
    - a2: entero que representa el coeficiente de grado 2
Descripcion:
    Se encarga de evaluar el polinomio en el punto x
"""
def evaluar_polinomio(secreto, x, a1, a2):
    fx = (secreto + a1*x + a2*x*x) % PRIME
    return (x, fx)

"""
Nombre funcion: generar_secreto
Parametros:
    - Ninguno
Descripcion:
    Se encarga de generar el secreto con ayuda de la libreria secrets
"""
def generar_secreto():
    secreto_bytes = secrets.token_bytes(32)
    secreto = int.from_bytes(secreto_bytes, "big")
    a1, a2 = generar_coeficientes()
    return (secreto, secreto_bytes, a1, a2)

"""
Nombre funcion: li
Parametros:
    - i: indice del punto bawse
    - puntos: lista de tuplas (x, f(x)) las partes del secreto
Descripcion:
    Se encarga de calcular la base de lagrange del indice i en los puntos
"""
def li(i, puntos):
    xi = puntos[i][0]
    mult = 1
    for j in range(len(puntos)):
        xj = puntos[j][0]
        if(xi != xj):
            mult = mult * ((-xj % PRIME) * pow((xi - xj) % PRIME, -1, PRIME))
    return mult % PRIME

"""
Nombre funcion: interpolacion_lagrange
Parametros:
    - puntos: lista de tuplas (x, f(x)) las partes del secreto
Descripcion:
    Utiliza la interpolacion de lagrange para decifrar el secreto
"""
def interpolacion_lagrange(puntos):
    secreto = 0
    for i in range(len(puntos)):
        yi = puntos[i][1]
        Li = li(i, puntos)
        secreto = (secreto + yi * Li) % PRIME
    return secreto

"""
Nombre funcion: guardar_claves
Parametros:
    - secreto_bytes: bytes que representan el secreto original
    - f1: tupla (x, f(x)) de la parte 1
    - f2: tupla (x, f(x)) de la parte 2
    - f3: tupla (x, f(x)) de la parte 3
    - f4: tupla (x, f(x)) de la parte 4
Descripcion:
    Se encarga de guardar (agrega a las ya existentes) las claves y sus llaves en archivos separados
"""
def guardar_claves(secreto_bytes, f1, f2, f3, f4):
    with open("CODIGO/keys/llaves_fase4.txt", "a") as f:
        f.write(f"Llave: {secreto_bytes.hex()}\n")
    with open("CODIGO/keys/partes_fase4.txt", "a") as f:
        f.write("\n")
        f.write(f"Parte 1: {f1}\n")
        f.write(f"Parte 2: {f2}\n")
        f.write(f"Parte 3: {f3}\n")
        f.write(f"Parte 4: {f4}\n")

"""
Nombre funcion: simulacion
Parametros:
    - f1: tupla (x, f(x)) de la parte 1
    - f2: tupla (x, f(x)) de la parte 2
    - f3: tupla (x, f(x)) de la parte 3
    - f4: tupla (x, f(x)) de la parte 4
    - secreto: entero que representa el secreto original
Descripcion:
    Simula todos los casos posibles con 1 2 3 y 4 partes para poder acceder al secreto
"""
def simulacion(f1, f2, f3, f4, secreto):
    partes = [f1, f2, f3, f4]
    nombres = {f1: "f1", f2: "f2", f3: "f3", f4: "f4"}
    print(f"\nSecreto original: {secreto}")
    print("=======SIMULACION DE CASOS DE USO DE LAS PARTES DEL SECRETO=======")
    for k in range(len(partes), 0, -1):
        if(k >= 3):
            print(f"=======Exito esperado con {k} partes=======")
        elif (k == 1):
            print(f"=========Fallo esperado con 1 parte========")
        else:
            print(f"=======Fallo esperado con {k} partes=======")
        combos_vistos = set()
        for combo in combinations(partes, k):
            for perm in permutations(combo):
                key = tuple(p[0] for p in perm)
                if key not in combos_vistos:
                    combos_vistos.add(key)
                    nombre = "+".join(nombres[p] for p in perm)
                    resultado = secreto == interpolacion_lagrange(list(perm))
                    print(f"{nombre}: {resultado}")
    print("\n")

if __name__ == "__main__":
    secreto, secreto_bytes, a1, a2 = generar_secreto()
    f1 = evaluar_polinomio(secreto, 1, a1, a2)
    f2 = evaluar_polinomio(secreto, 2, a1, a2)
    f3 = evaluar_polinomio(secreto, 3, a1, a2)
    f4 = evaluar_polinomio(secreto, 4, a1, a2)
    guardar_claves(secreto_bytes, f1, f2, f3, f4)
    simulacion(f1, f2, f3, f4, secreto)