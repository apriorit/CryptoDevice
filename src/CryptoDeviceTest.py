import io
import os
import sys
import hashlib
import subprocess

TEST_EXE = "CryptoDeviceTest.exe"
TEST_FILE = "CryptoDeviceTestFile.txt"
TEST_FILE_HASH = ""
TEST_FILE_LINE = "1" * 1000
TEST_FILE_LINE_COUNT = 1000000

def sha256(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()
    
def run_test(command):
    print("Run [" + command + "]")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    
    (stdout, _) = process.communicate()
    output = [s for s in stdout.decode('utf-8').splitlines()]
      
    if process.returncode != 0:
        raise ValueError("Error", process.returncode)
        
    print("    >> " + "\n    >> ".join(output), "\n\n")
    return output

def find_string(lines, pattern):
    for line in lines:
        if line.startswith(pattern):
            return True
    raise ValueError("Cannot find [" + pattern + "]")

def create_test_file():
    with open(TEST_FILE, "w") as file:
        for _ in range(TEST_FILE_LINE_COUNT):
            file.write(TEST_FILE_LINE)
            file.write(os.linesep)
            
def check_sha256():
    cmd = "(echo hash " + TEST_FILE + " & echo exit) | " + TEST_EXE
    output = run_test(cmd)

    hash_pattern = TEST_FILE + "  : "
    for line in output:
        if line.startswith(hash_pattern):
            hash = line[len(hash_pattern):].strip()
            print("Device hash:", "["+hash+"]")
            print("File hash  :", "["+TEST_FILE_HASH+"]")
            if hash.lower() != TEST_FILE_HASH.lower():
                raise ValueError("Hashes are not equal")
            return 
    raise ValueError("Cannot calc HASH, pattern: '" + hash_pattern + "'")
            
def check_aes_cbc():
    cmd_encrypt = "(echo encrypt " + TEST_FILE + " & echo exit) | " + TEST_EXE
    output = run_test(cmd_encrypt)
    find_string(output, "File '{} ' encrypted".format(TEST_FILE))
    
    hashfile_encrypted = sha256(TEST_FILE)
    print("Sha2 before:", TEST_FILE_HASH)
    print("Sha2 after :", hashfile_encrypted)
    
    if hashfile_encrypted.lower() == TEST_FILE_HASH.lower():
        raise ValueError("File was not encrypted")
    
    # input("Press Enter to encrypt the file...")
    
    cmd_decrypt = "(echo decrypt " + TEST_FILE + " & echo exit) | " + TEST_EXE
    output = run_test(cmd_decrypt)
    find_string(output, "File '{0} ' decrypted".format(TEST_FILE))
    
    hashfile_decrypted = sha256(TEST_FILE)
    print("Sha2 orig  :", TEST_FILE_HASH)
    print("Sha2 after :", hashfile_decrypted)
    if TEST_FILE_HASH.lower() != hashfile_decrypted.lower():
        raise ValueError("File was not decrypted")
        
def check_reset():
    cmd = "(echo reset & echo exit) | " + TEST_EXE
    output = run_test(cmd)
    find_string(output, "> Reset done")
    
def check_status():
    cmd = "(echo status & echo exit) | " + TEST_EXE
    output = run_test(cmd)
    find_string(output, "> State:")
    find_string(output, "Error:")
    
def check_devices():
    cmd = "(echo devices & echo exit) | " + TEST_EXE
    output = run_test(cmd)
    find_string(output, r"> \\?\PCI#VEN_1111&DEV_2222&")
    
def check_unittests():
    cmd = TEST_EXE + " --unit_tests " 
    output = run_test(cmd)
    find_string(output, "[  PASSED  ] 58 tests.")

class Tee(object):
    def __init__(self, std, name):
        self.stdwrite = std.write
        self.name = name
        std.write = self.writewrap
        if os.path.isfile(name):
            os.remove(name)
    def writewrap(self, data):
        with open(self.name, "a", encoding='utf-8') as log:
            log.write(data)
        self.stdwrite(data.encode(sys.stdout.encoding, errors='replace').decode(sys.stdout.encoding))
    
if __name__ == "__main__":
    
    tee1 = Tee(sys.stdout, "CryptoDeviceTest.log")
    tee2 = Tee(sys.stderr, "CryptoDeviceTest.log")
    
    print("Creating test file...")
    create_test_file()
    TEST_FILE_HASH = sha256(TEST_FILE)
    print("Test file has been created", TEST_FILE, "hash:", TEST_FILE_HASH)
    
    check_sha256()
    print("Test HASH passed")
    
    check_aes_cbc()
    print("Test AES passed")
    
    check_reset()
    print("Test reset passed")
    
    check_status()
    print("Test status passed")
    
    check_devices()
    print("Test devices passed")
    
    check_unittests()
    print("Test unit tests passed")
    
    os.remove(TEST_FILE)
    input("Press Enter to exit...")
    

