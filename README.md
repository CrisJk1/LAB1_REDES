# Laboratorio 1 - Redes de Computadores - GRUPO 1
El informe junto con el enunciado estan en la carpeta `PDF/`. El codigo esta en la carpeta `CODIGO/`.

## Ejecucion
1. Setup del entorno:
    ```bash
    make setup
    ```
2. Ejecutar todas las fases:
    ```bash
    make run
    ```

## Fase 2
Para ejecutar solo la fase 2:
```bash
make fase2
```

El programa pedira el nombre de la key. Ese nombre debe coincidir exactamente con la carpeta dentro de `CODIGO/keys/`. Por ejemplo, si existen:
```text
CODIGO/keys/mi_nombre/mi_nombre_pub.pem
CODIGO/keys/mi_nombre/mi_nombre_priv.pem
CODIGO/keys/mi_nombre/mi_nombre_salt.bin
```
entonces se debe ingresar:
```text
mi_nombre
```

La fase 2 consume:
- `CODIGO/data/silo_manifesto.txt`: archivo de texto que se cifra y descifra con cifrado hibrido.
- `CODIGO/data/silo_circuito.bmp`: imagen usada para comparar ECB vs CBC.
- `CODIGO/keys/<nombre>/<nombre>_pub.pem`: llave publica del destinatario.
- `CODIGO/keys/<nombre>/<nombre>_priv.pem`: llave privada para recuperar la clave de sesion.

La fase 2 genera archivos en `CODIGO/outputs/fase2/`:
- `hybrid/`: ciphertext, clave de sesion cifrada, IV, archivo descifrado y metadata.
- `bmp_demo/`: imagen cifrada con ECB, imagen cifrada con CBC, IV de CBC y metadata.

## Para el Equipo
Para hacer el setup, ejecutar las fases, compilar el informe y armar el targz, ejecutar:
```bash
make all
```
