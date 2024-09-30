import random
import time
from datetime import datetime

# Function to generate a random IP address
def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# Intrusion types
intrusion_types = ['benign', 'bot', 'portscan', 'ddos']

# Open the file for writing
with open('intrusion_log.txt', 'w') as log_file:
    for _ in range(1000):
        # Generate log entry details
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        intrusion_type = random.choice(intrusion_types)
        src_ip = generate_ip()
        dst_ip = generate_ip()
        
        # Write the log entry
        log_entry = f"{timestamp} - {intrusion_type.upper()} detected from {src_ip} to {dst_ip}\n"
        log_file.write(log_entry)
        
        # Simulate time delay between entries (optional)
        time.sleep(0.01)  # You can adjust this for more or less delay between logs

print("intrusion_log.txt file generated with 1000 entries.")
