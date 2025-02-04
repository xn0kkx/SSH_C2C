import paramiko
import threading
import getpass
import os

# Lock to safely access the shared results dictionary
results_lock = threading.Lock()

def execute_command(host, user, password, command, keyfile, results):
    """
    Executes a command on a remote server via SSH and stores the results in the 'results' dictionary.

    The 'results' dictionary will contain, for each host, information about:
      - Whether the connection was established
      - Standard output (stdout) and error output (stderr) of the command
      - Connection error messages, if any
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Accepts unknown hosts

        # Connect using RSA key or password
        if keyfile:
            if not os.path.isfile(keyfile):
                with results_lock:
                    results[host] = {
                        "connection": False,
                        "error": f"RSA key file not found: {keyfile}"
                    }
                return
            # Load the private key
            private_key = paramiko.RSAKey.from_private_key_file(keyfile)
            client.connect(hostname=host, username=user, pkey=private_key, timeout=10)
        else:
            client.connect(hostname=host, username=user, password=password, timeout=10)

        # Connection established successfully
        with results_lock:
            results[host] = {"connection": True}

        # Execute the command
        _, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        error  = stderr.read().decode().strip()

        with results_lock:
            results[host].update({
                "stdout": output,
                "stderr": error
            })

        client.close()

    except Exception as e:
        with results_lock:
            results[host] = {
                "connection": False,
                "error": str(e)
            }

def main():
    # User input
    hosts = input("Enter hosts (separated by commas): ").strip().split(',')
    # Remove extra whitespace and empty values
    hosts = [host.strip() for host in hosts if host.strip()]
    
    user = input("User: ").strip()

    # Choose authentication method
    method = ''
    while method not in ['1', '2']:
        print("\nSelect the authentication method:")
        print("1 - Password")
        print("2 - RSA Key")
        method = input("Type 1 or 2: ").strip()

    password = None
    keyfile = None

    if method == '1':
        password = getpass.getpass("Password: ")
    else:
        keyfile = input("Enter the full path to the RSA key file: ").strip()

    print("\nRemote shell started. Type 'exit' or 'quit' to close.")

    while True:
        command = input("\nEnter a command: ").strip()
        if command.lower() in ['exit', 'quit']:
            print("Closing the shell...")
            break

        # Dictionary to store the results of the current command
        results = {}

        # Create a thread for each host
        threads = []
        for host in hosts:
            thread = threading.Thread(
                target=execute_command,
                args=(host, user, password, command, keyfile, results)
            )
            thread.start()
            threads.append(thread)

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        # Display the results for each host
        print("\n===== RESULTS =====")
        for host in hosts:
            info = results.get(host, {})
            print(f"\nHost: {host}")
            if not info.get("connection", False):
                print("Connection: NOT established")
                print(f"Error: {info.get('error', 'No details available')}")
            else:
                print("Connection: Established")
                print("Command Output:")
                print(info.get("stdout", "No output"))
                if info.get("stderr"):
                    print("Errors:")
                    print(info.get("stderr"))

if __name__ == "__main__":
    main()
