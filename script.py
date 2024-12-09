import csv
import re

def analyze_log(log_file_path, failed_attempt_threshold=10):
    """Analyzes the log file for request counts, most accessed endpoints, and suspicious activity."""
    
    
    ip_request_counts = {}
    endpoint_access_counts = {}
    failed_login_attempts = {}

    # Read and analyze each line of the log file
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            if not ip_match:
                continue  
            ip_address = ip_match.group()

            endpoint_match = re.search(r'\"(?:GET|POST) (.*?) HTTP', line)
            if not endpoint_match:
                continue  
            endpoint = endpoint_match.group(1)

            status_code_match = re.search(r'HTTP/\d\.\d" (\d{3})', line)
            if not status_code_match:
                continue  
            status_code = int(status_code_match.group(1))

            ip_request_counts[ip_address] = ip_request_counts.get(ip_address, 0) + 1

            endpoint_access_counts[endpoint] = endpoint_access_counts.get(endpoint, 0) + 1

            if status_code == 401:
                failed_login_attempts[ip_address] = failed_login_attempts.get(ip_address, 0) + 1

    
    sorted_ip_requests = sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True)

    most_frequently_accessed_endpoint = max(endpoint_access_counts, key=endpoint_access_counts.get)

    sorted_failed_logins = sorted(
        [(ip, count) for ip, count in failed_login_attempts.items() if count > failed_attempt_threshold],
        key=lambda x: x[1], 
        reverse=True
    )

    print("\n--- Requests per IP ---")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count:<15}")

    print("\n--- Most Frequently Accessed Endpoint ---")
    print(f"{most_frequently_accessed_endpoint} (Accessed {endpoint_access_counts[most_frequently_accessed_endpoint]} times)")

    print("\n--- Suspicious Activity Detected ---")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    for ip, count in sorted_failed_logins:
        print(f"{ip:<20} {count:<15}")

    with open('log_analysis_results.csv', 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)

        #Requests per IP
        csv_writer.writerow(['IP Address', 'Request Count'])
        csv_writer.writerows(sorted_ip_requests)

        csv_writer.writerow([])  

        #Most Accessed Endpoint
        csv_writer.writerow(['Most Frequently Accessed Endpoint', 'Access Count'])
        csv_writer.writerow([most_frequently_accessed_endpoint, endpoint_access_counts[most_frequently_accessed_endpoint]])

        csv_writer.writerow([])  
        
        #Suspicious Activity
        csv_writer.writerow(['IP Address', 'Failed Login Attempts'])
        csv_writer.writerows(sorted_failed_logins)

analyze_log('server.log')
