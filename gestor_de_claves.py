import sys
import os
import json
import hashlib
from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re
import time

USERFILE='userfile'
KEYSFILE='keys'

def main():
    try:
        clear_term()
        if not authenticate_user():
            sys.exit()
        checkToken()
        while True:
            clear_term() 
            
            print("Bienvenido al Simple Gestor de Claves")
            print("Selecciona una opcion")
            print("    (1) Ver claves guardadas\n    (2) Agregar clave\n    (3) Eliminar clave\n    (4) Salir")
            action = input("->")
            if action=="1":
                inspect_keys()
            elif action=="2":
                create_keys()
            elif action=="3":
                delete_keys()
            elif action=="4":
                sys.exit()
            else:
                print("por favor, selecciona una de las opciones")
                input("presiona una tecla para regresar...")
                continue
            continue
    except KeyboardInterrupt:
        sys.exit()

def inspect_keys():
    # search for file that contains keys ("keys.js")
    # if not found, no keys. If found display keys
    if keysFileExists():
        with open(KEYSFILE,"rb") as file:
            decrypted = fernet_obj.decrypt(file.read())
            json_string = decrypted.decode('utf-8')
            json_obj = json.loads(json_string)
            print(json.dumps(json_obj, indent=4))
            input("presiona una tecla para regresar...")
        return
    print("no se encuentran registros")
    input("presiona una tecla para regresar...")

def create_keys():
    if keysFileExists():
        print("Introduce el titulo de la clave")
        title = input("->")
        if titleExists(title):
            print("la clave ingresada ya esta registrada")
            input("presiona una tecla para regresar...")
            return
        else:
            while (True):
                print("Introduce la clave, o introduce 'q' para salir")
                key = input()
                if key=='q':
                    return

                print("Confirma la clave")
                key_confirm = input()
                if key!=key_confirm:
                    print("las claves no coinciden")
                    input("presiona una tecla para internarlo de nuevo")
                    continue
                else:
                    with open(KEYSFILE,"rb") as file:
                        decrypted = fernet_obj.decrypt(file.read())
                        json_string = decrypted.decode('utf-8')
                        file_json = json.loads(json_string)
                        # add new key with title as key and key as value in variable
                        file_json[title] = key
                    with open(KEYSFILE,"wb") as file:
                        json_string = json.dumps(file_json)
                        encrypted = fernet_obj.encrypt(json_string.encode('utf-8'))
                        file.write(encrypted)
                    break
            print("clave guardada con exito")
            input("presiona una tecla para regresar...")
        return
    else:
        # 'keys' doesnt exist
        print("Agregando una clave por primera vez...")
        print("Introduce el titulo de la clave")
        title = input()
        while (True):
            print("Introduce la clave, o introduce 'q' para salir")
            key = input()
            if key=='q':
                return

            print("Confirma la clave")
            key_confirm = input()
            if key!=key_confirm:
                print("las claves no coinciden")
                input("presiona una tecla para intentarlo de nuevo")
                continue
            else:
                with open(KEYSFILE,"xb") as file:
                    file_json = {title:key}
                    # encrypt data, then fill file with it
                    encrypted = fernet_obj.encrypt(json.dumps(file_json).encode("utf-8"))
                    file.write(encrypted)
                break
        print("se ha creado el archivo 'keys'")
        print("clave guardada con exito")
        input("presiona una tecla para regresar...")
    return

def delete_keys():
    # if file doesnt exist, output "no keys" redirect
    # if file does exist, ask which key they wish to delete.
    # then delete key
    if not keysFileExists():
        print("no hay claves guardadas")
        input("presiona una tecla para regresar")
        return
    else:
        while True:
            print("Escribe el titulo de la clave que deseas eliminar")
            title = input()
            if not titleExists(title):
                print("el titulo no existe")
                input("presiona una tecla para regresar")
                return

            confirm = input(f"deseas eliminar la clave {title.lower()}? (si/no)")
            if confirm=="no":
                print("presiona una tecla para regresar")
                input()
                return
            elif confirm=="si":
                title = title.lower()
                with open(KEYSFILE,"rb") as file:
                    decrypted = fernet_obj.decrypt(file.read())
                    json_string = decrypted.decode('utf-8')
                    file_json = json.loads(json_string)
                file_json.pop(title)
                with open(KEYSFILE,"wb") as file:
                    json_string = json.dumps(file_json)
                    encrypted = fernet_obj.encrypt(json_string.encode('utf-8'))
                    file.write(encrypted)
                break
            else:
                print("por favor introduce una de las opciones (si/no)")
                input("presiona una tecla para volver a intentarlo")
                continue
    print(f"se ha eliminado el titulo {title} con exito")
    input("presiona una tecla para regresar")




def keysFileExists():
    files = os.listdir()
    for file in files:
        if file==KEYSFILE:
            return True
    return False

def titleExists(title):
    with open(KEYSFILE,"rb") as file:
        decrypted = fernet_obj.decrypt(file.read())
        json_string = decrypted.decode('utf-8')
        file_json = json.loads(json_string)
        if file_json.get(title.lower()):
            return True
        else:
            return False

def clear_term():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def validate_password(password):
    with open(USERFILE,'rb') as file:
        hash_obj = hashlib.sha256()
        hash_obj.update(password.encode('utf-8'))
        if file.read(32)==hash_obj.digest():
            salt = file.read()
            global fernet_obj
            fernet_obj = generate_fernet_obj(password, salt)
            return True
        else:
            if __name__ == "__main__":
                print("la clave no es correcta")
                input("presiona una tecla para regresar")
            return False

def authenticate_user():
    if userFileExists():
        print("introduce tu clave para ingresar")
        password = input("->")
        return validate_password(password)
    else:
        while True:
            password = passwordCreation()
            print("Confirma la llave secreta")
            pass_confirm = input("->")
            if password!=pass_confirm:
                print("las llaves no coinciden")
                input("presiona una tecla para intentarlo de nuevo")
                continue
            
            # create userfile that contains hashed pass
            with open(USERFILE,"xb") as file:
                hash_obj = hashlib.sha256()
                hash_obj.update(password.encode('utf-8'))
                file.write(hash_obj.digest())
                file.write(os.urandom(16)) # salt for fernet
				
            # call "validate" so fernet object is created for newly created account
            validate_password(password)
            break
    print("cuenta registrada con exito")
    input("presiona una tecla para ir al inicio")
    return True 


def userFileExists():
    files = os.listdir()
    for file in files:
        if file==USERFILE:
            return True
    return False

def generate_fernet_obj(password, salt):
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return Fernet(key)

def passwordCreation():
    clear_term()
    print("no se ha creado una cuenta, creando cuenta...")
    time.sleep(0.5)
    reg_numbers = r'\d'    
    reg_symbols = r'[^0-9a-zA-Z ]'
    reg_uppercase = r'[A-Z]'
    reg_lowercase = r'[a-z]'

    while True:
        print("crea una llave secreta para acceder al gestor, o introduce 'q' para salir")
        print('''debe contener al menos:
        -dos numeros
        -dos simbolos
        -dos mayusculas
        -dos minusculas
        -doce caracteres en total''')
        password = input("->")
        if password=='q':
            sys.exit()

        pass_numbers_amount = len(re.findall(reg_numbers, password))
        pass_symbols_amount = len(re.findall(reg_symbols, password))
        pass_uppercase_amount = len(re.findall(reg_uppercase, password))
        pass_lowercase_amount = len(re.findall(reg_lowercase, password))
        pass_character_amount = len(password)
        print(f'''la llave contiene:
        -{pass_numbers_amount}/2 numeros
        -{pass_symbols_amount}/2 simbolos
        -{pass_uppercase_amount}/2 mayusculas
        -{pass_lowercase_amount}/2 minusculas
        -{pass_character_amount}/12 caracteres''')
        
        if (pass_numbers_amount >= 2) and (pass_symbols_amount >= 2) and (pass_uppercase_amount >= 2) and (pass_lowercase_amount >= 2) and (pass_character_amount >= 12):
            break
        else:
            print("la clave es muy debil")
            input("presiona una tecla para regresar")
            clear_term()
            continue
    return password

def checkToken():
    if keysFileExists():
        try:
            with open(KEYSFILE,"rb") as file:
                decrypted = fernet_obj.decrypt(file.read())
        except (InvalidToken, InvalidSignature):
            print("ERROR: El archivo de llaves no corresponde a la cuenta.\nlas llaves en el archivo 'keys' no pudieron ser leidas por las credenciales de 'userfile'")
            print("\nQuita el archivo 'keys' para generar uno nuevo, o utiliza el archivo 'userfile' correcto")
            input("presiona una tecla para salir")
            sys.exit()

if __name__ == "__main__":
    main()

