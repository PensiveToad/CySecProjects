import argparse

def get_arg():
    
    parser = argparse.ArgumentParser(description='CaesarCipher Encrypt/Decrypt')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', '--encrypt', nargs='+', dest='encrypt_target')
    group.add_argument('-d', '--decrypt', help='Input text even if decrypting file path', dest='decrypt_target')
    parser.add_argument('-f', '--filePath', dest='filePath')
    opt = parser.parse_args()
    
    if not opt.encrypt_target and not opt.decrypt_target:
        parser.error('[!] Please enter an input for either encrypt or decrypt')
        
    if opt.encrypt_target:
        caesarCipher.encrypt = True
    else:
        caesarCipher.decrypt = True
        
    return opt
    
class caesarCipher: # Setting up class variables for use in functions.
        
    SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'
    key = 13
    encrypt = False
    decrypt = False

def getMessage(secret_message): # Iterates through the message, finding matching characters, their numerical placement, and sending them to the right function.
    
    translated = ''
    SYMBOLS = caesarCipher.SYMBOLS
    num = ''
    
    for symbol in secret_message: 
        if symbol in SYMBOLS:
            symbolIndex = SYMBOLS.find(symbol)
            if caesarCipher.encrypt:
                translatedIndex = encryptMessage(symbolIndex)
            elif caesarCipher.decrypt:
                translatedIndex = decryptMessage(symbolIndex)
                
            if translatedIndex >= len(SYMBOLS): # Handling the wraparound of SYMBOLS
                translatedIndex = translatedIndex - len(SYMBOLS)
            elif translatedIndex < 0:
                translatedIndex = translatedIndex + len(SYMBOLS)
                
            translated = translated + SYMBOLS[translatedIndex]
        else:
            translated = translated + symbol
            
    return translated

def encryptMessage(encrypt_symbol): # encryption function
    result = encrypt_symbol + caesarCipher.key
    return result
    

def decryptMessage(decrypt_symbol): # decryption function
    result = decrypt_symbol - caesarCipher.key
    return result

def writeFile(file_message, file_path): # writing encryption text to file at directory or file path.
    
    if not file_path:
        file = open(file_message + '.txt', 'x')
        file.write(file_message)
        file.close()
    else:
        print('Complete')
        file_name = file_path + file_message + '.txt'
        file = open(file_name, 'x')
        file.write(file_message)
        file.close()
        
def readFile(file_path): # reading the text at the end of specified file path.
    
    if not file_path:
        raise Exception('[!]Decrypt: File Path is empty. Please enter a file path')
    else:
        file = open(file_path, 'r')
        return file.read()
    
def main():
    opt = get_arg()
    
    
    # checkng whether to encrypt or decrypt and run read/write functions.
    if caesarCipher.encrypt:
        inputMessage = ' '.join(opt.encrypt_target)
        translated_message = getMessage(inputMessage)
        writeFile(translated_message, opt.filePath)
            
    elif caesarCipher.decrypt:
        if opt.filePath:
            input_message = readFile(opt.filePath)
            translated_message = getMessage(input_message)
        else:
            translated_message = getMessage(opt.decrypt_target)
        print(translated_message)
            
main()