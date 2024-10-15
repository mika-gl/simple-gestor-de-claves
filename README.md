# Descripción
Gestor simple de claves escrito en Python.  
Uso mediante CLI. Opciones para Inspeccionar, Crear y Eliminar claves del usuario.  

Utiliza el módulo Fernet para la encriptación simétrica con AES de las llaves almacenadas:  
Segun la [documentación](https://cryptography.io/en/latest/fernet/):  
> AES in CBC mode with a 128-bit key for encryption; using PKCS7 padding  
> HMAC using SHA256 for authentication  
> Initialization vectors are generated using os.urandom()  



La credenciales del usuario para acceder al gestor se guardan en el archivo 'userfile' en formato SHA-256.  
El archivo ademas contiene la 'salt' para la decryptación de las claves almacenadas en 'keys' de ese usuario.  

Validación de la clave elegida por el usuario para acceder al gestor, de manera que no sea trivial.  


# Para utilizar
*Se debe tener Python instalado  
Se debe descargar únicamente el archivo 'gestor_de_claves.py' y ejecutarlo idealmente dentro de una carpeta asignada.  
El script se ocupa de crear los archivos 'userfile' y 'keys' al momento de definir las credenciales y agregar las llaves.  
