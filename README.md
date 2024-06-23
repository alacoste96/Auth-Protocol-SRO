# Auth-Protocol-SRO
# PRÁCTICA PROTOCOLO DE AUTENTICACIÓN. 3º ING. TELEMÁTICA. SRO.
## Autor: Alexandre Lacoste Rodríguez 



## Peculiaridades

Para hacer el servidor y el cliente he usado el lenguaje de 
programación C puro en ambos, así como en el fichero "tools.c" que se adjunta,
del cual, tanto el server como el cliente usan herramientas comunes a ambos; es
imperativo que los 3 ficheros se encuentren en el mismo directorio; si no lo
quiere de esta manera, tendrá que modificar el #include "tools.c" y especificar
la ruta donde se encuentre el fichero "tools.c".
La dirección IP en la que escuchará el servidor por defecto es 127.0.0.1.

## Servidor


Deberá incluir un primer argumento especificando un fichero de texto que 
corresponda a los nombres de usuario con sus claves en hexadecimal siguiendo 
el siguiente formato en cada línea: <usuario>:<clave> 

Las claves deben tener un total de 40 caracteres hexadecimales; ni más ni menos.
Los nombres de usuarios deberán tener como máximo 255 caracteres y no se 
permiten caracteres especiales.

**COMPILACIÓN:**

```bash
gcc -Wall authserver.c -lssl -lcrypto -o authserver
```
**EJECUCIÓN**


Se deberá facilitar en el primer argumento el fichero de texto donde se 
encuentren las cuentas con sus claves; en el ejemplo a continuación usaremos
"accounts.txt".

Se le podrá facilitar un segundo argumento opcional especificando el puerto.
Si no se facilita este argumento o es incorrecto(no es un un numero)
se usará el puerto 9999 por omisión.

Ejemplo:
```bash
./authserver accounts.txt 7777
```

## Cliente

**COMPILACIÓN:**

```bash
gcc -Wall authclient.c -lssl -lscrypto -o authclient
```

**EJECUCIÓN**


Se deberá facilitar un primer argumento que corresponda al nombre de usuario. El
nombre deberá ser menor de 255 caracteres y no se admiten caracteres especiales.

Un segundo argumento que corresponda a la clave de dicho usuario en hexadecimal.
La clave constará de 40 caracteres en hexadecimal, ni uno más ni uno menos.

Un tercer argumento que correspona a la dirección IP en la que está escuchando
el server.

Un cuarto y último argumento que corresponde al puerto en el que está escuchando
el servidor. Por defecto, si este campo es incorrecto se usará el puerto 9999 
pero es obligatorio incluirlo.

Ejemplo:

```bash
./authclient pepe 3f786850e387550fdab836ed7e6dc881de23001b 127.0.0.1 9999
```
