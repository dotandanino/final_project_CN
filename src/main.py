import pyshark
import matplotlib.pyplot as plt
import nest_asyncio
nest_asyncio.apply()
#ip header - A
# By protocols per application
'''
Extracts packets from a file and creates a pie chart showing the distribution of transport layer protocols (TCP, UDP, QUIC, DNS, OTHER).
'''
def create_protocol_plot(filename):
    record = pyshark.FileCapture(filename, keep_packets=False) #extract packets
    udp = 0
    tcp = 0
    quic = 0
    dns = 0
    other = 0
    total_msg_amount = 0
    for packet in record:
        protocol = packet.transport_layer #extracting the protocol from the record
        if protocol == "UDP": # UDP can be QUIC, DNS or just UDP
            if hasattr(packet, "quic"):
                quic = quic + 1
            elif hasattr(packet, "dns"):
                dns += 1
            else:
                udp = udp + 1
        elif protocol == "TCP":
            tcp = tcp + 1
        else:
            other = other + 1
    total_msg_amount = udp + tcp + other + quic + dns
    if total_msg_amount==0:
        total_msg_amount=1
    print(f"The counter are \nTOTAL:{total_msg_amount}\nUDP: {udp}\nTCP: {tcp}\nQUIC: {quic}\n,DNS:{dns}\nOTHER: {other}")
    sizes = [tcp / total_msg_amount, udp / total_msg_amount, quic / total_msg_amount,dns/total_msg_amount, other / total_msg_amount]
    labels = ["TCP", "UDP", "QUIC","DNS","OTHER"]
    colors = ['#ff7f0e', '#17becf', '#2ca02c', '#d62728', '#1f77b4']
    labels_with_percentages = []
    for label, size in zip(labels, sizes):#zip - create list of tuples
        formatted_label = f"{label} ({size * 100:.1f}%)" #format as percentage
        labels_with_percentages.append(formatted_label)
    plt.pie(sizes, colors=colors, startangle=90)
    plt.title(filename.split('.')[0], pad=20, fontsize=20)
    plt.legend(labels_with_percentages, loc="lower right")
    plt.axis('equal')
    plt.show()
'''
 Calculates the average Time-To-Live (TTL) value from packets in a given pcap file.
'''
# By TTL - average of all applications
def calculate_ttl_average(filename):  #culc ttl from given pacp
    record = pyshark.FileCapture(filename, keep_packets=False) #extract all packets
    ttl_values = []

    for packet in record:
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'ttl'): #collect all TTL values
            ttl = int(packet.ip.ttl)
            ttl_values.append(ttl)

    if ttl_values:
        average_ttl = sum(ttl_values) / len(ttl_values)  # collect all TTL values
        return average_ttl
    else:
        return 0
"""
Creates a bar chart comparing the average TTL values between different applications.
"""
def create_ttl_comparison_plot(applications):
    app_names = list(applications.keys())
    ttl_averages = [calculate_ttl_average(applications[app]) for app in app_names]#
    colors = ['#ff7f0e', '#17becf', '#2ca02c', '#d62728', '#1f77b4']  # different colors for each bar
    plt.bar(app_names, ttl_averages, color=colors, width=0.5)
    plt.xlabel('Application')
    plt.ylabel('Average TTL')
    plt.title('Average TTL Comparison Between Applications')

    for i, v in enumerate(ttl_averages):
        plt.text(i, v + 0.5, str(round(v, 2)), color='black', ha='center')

    plt.show()
# tcp header - B
'''
Calculates the average TCP window size from packets in a given pcap file.
'''
def calculate_window_size_average(filename):
    record = pyshark.FileCapture(filename, keep_packets=False)
    window_sizes = []

    for packet in record:#
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'window_size_value'):
            window_size = int(packet.tcp.window_size_value)
            window_sizes.append(window_size)

    if window_sizes:
        average_window_size = sum(window_sizes) / len(window_sizes)
        return average_window_size
    else:
        return 0
'''
  Creates a bar chart comparing the average TCP window sizes between different applications.
'''
def create_window_size_comparison_plot(applications):  # culc the average between all apps
    app_names = list(applications.keys())
    window_size_averages = [calculate_window_size_average(applications[app]) for app in app_names]#Calculate window size averages for each application
    colors = ['#ff7f0e', '#17becf', '#2ca02c', '#d62728', '#1f77b4']
    plt.bar(app_names, window_size_averages, color=colors, width=0.5)
    plt.xlabel('Application')
    plt.ylabel('Average Window Size (Bytes)')
    plt.title('Average Window Size Comparison Between Applications')

    for i, v in enumerate(window_size_averages):
        plt.text(i, v + 0.5, str(round(v, 2)), color='black', ha='center')

    plt.show()
#in port / out port
def capture_filtered_packets(filename, port_filter):
    capture = pyshark.FileCapture(filename, display_filter=port_filter)# Capture packets with filter
    packets = [pkt for pkt in capture]
    capture.close()
    print("packets:", len(packets))#  Print the number of packets captured
    return packets

'''
 Counts packets by source port and destination port if they are below 8192.
'''
def count_packets_by_src_port(packets):
    port_counts = {}
    print("packets:", len(packets))# Print the number of packets processed
    for packet in packets:#
        if hasattr(packet, 'tcp'):
            src_port = int(packet.tcp.srcport)# Extract source port
            dst_port = int(packet.tcp.dstport)# Extract destination port
            if src_port<8192:
                if str(src_port) not in port_counts:
                    port_counts[str(src_port)] = 0
                port_counts[str(src_port)] += 1
            if dst_port<8192:#
                if str(dst_port) not in port_counts:
                    port_counts[str(dst_port)] = 0
                port_counts[str(dst_port)] += 1

    return port_counts
'''
Filters ports by their traffic percentage, keeping only those above a certain threshold.
'''
def filter_ports_by_traffic(port_counts, threshold_percentage):
    total_packets = sum(port_counts.values())
    filtered_port_counts = {port: count for port, count in port_counts.items() if (count / total_packets) >= (threshold_percentage / 100)}#
    return filtered_port_counts

'''
 Plots a bar chart showing the number of packets for each port.
'''
def plot_port_counts(port_counts,appname):
    if not port_counts:
        print("No packets found with the specified filter.")
        return
    print("port counts:", port_counts)

    ports = list(port_counts.keys())# Print the port counts
    counts = list(port_counts.values())# List of ports

    colors = ['#FF5733', '#33FF57', '#3357FF', '#FF33A8', '#A833FF', '#33FFF6', '#006400', '#FF8333', '#33FF83', '#8333FF']
    colors = colors * (len(ports) // len(colors) + 1)

    plt.bar(ports, counts, color=colors[:len(ports)], width=0.5)
    plt.xlabel('Port')
    plt.ylabel('Number of Packets')
    plt.title(f'Number of Packets by Port {appname}')
    plt.show()

#tls header - C

'''
 Extracts TLS versions from packets in a given pcap file and counts occurrences of each version.
'''
def get_tls_versions(file_name):
    version_map = {
        '0x0301': 'TLS 1.0 (Deprecated)',
        '0x0302': 'TLS 1.1 (Deprecated)',
        '0x0303': 'TLS 1.2',
        '0x0304': 'TLS 1.3'
    }

    tls_version_counts = {key: 0 for key in version_map.values()}#Initialize TLS version counts
    tls_version_counts['Unknown'] = 0

    capture = pyshark.FileCapture(file_name, display_filter="tls", keep_packets=False)# Capture TLS packets

    for packet in capture:#
        if 'TLS' in packet:
            if hasattr(packet.tls, 'record_version'):#Extract TLS version
                tls_version = packet.tls.record_version
                print (f"found tls version {tls_version}")
                if tls_version in version_map:#
                    tls_version_counts[version_map[tls_version]] += 1
                else:
                    tls_version_counts['Unknown'] += 1


    capture.close()

    # Print results
    print("\nTLS Version Counts:")
    for version, count in tls_version_counts.items():
        print(f"{version}: {count}")

    return tls_version_counts
'''
Counts TLS connections based on IP pairs with at least 5 connections.
'''
def count_tls_connections(packets):
    tls_connections = {}
    for packet in packets:
        if hasattr(packet, 'tls'):
            src_ip = packet.ip.src # Extract source IP
            dst_ip = packet.ip.dst # Extract destination IP
            if src_ip not in tls_connections:
                tls_connections[src_ip] = set()
            if dst_ip not in tls_connections:
                tls_connections[dst_ip] = set()

            tls_connections[src_ip].add(dst_ip)
            tls_connections[dst_ip].add(src_ip)

    connection_counts = {ip: len(connections) for ip, connections in tls_connections.items() if len(connections) >= 5} # Count connections with at least 5 pairs
    return connection_counts

'''
    Counts the maximum number of concurrent TLS connections from captured packets.
'''
def count_max_concurrent_tls_connections(packets):
    events = []

    for packet in packets:
        if hasattr(packet, 'tls'):
            timestamp = packet.sniff_time.timestamp() # Extract timestamp
            src_ip = packet.ip.src  # Extract source IP
            dst_ip = packet.ip.dst # Extract destination IP
            connection = (src_ip, dst_ip)

            # Event of starting a connection
            events.append((timestamp, "start", connection))

            # Event of ending a connection (arbitrary time of 1 second for example)
            events.append((timestamp + 1, "end", connection))

    # Sort events by time
    events.sort()

    # Count number of active connections at any point
    active_connections = set()
    max_concurrent = 0

    for timestamp, event_type, connection in events:
        if event_type == "start":
            active_connections.add(connection)
        elif event_type == "end" and connection in active_connections:
            active_connections.remove(connection)

        # Update max concurrent connections
        max_concurrent = max(max_concurrent, len(active_connections))

    return max_concurrent

'''
Plots a bar chart showing the maximum number of concurrent TLS connections for different applications.
'''
def plot_max_concurrent_tls(applications, colors):
    app_names = list(applications.keys())
    max_concurrent_counts = []

    for app_name, filename in applications.items():
        packets = capture_filtered_packets(filename, 'tls')  #Capture TLS packets
        max_concurrent = count_max_concurrent_tls_connections(packets) # Count max concurrent TLS connections
        max_concurrent_counts.append(max_concurrent)

    plt.rcParams.update({'font.size': 14,'axes.labelsize': 16,'axes.titlesize': 18,'xtick.labelsize': 14, 'ytick.labelsize': 14,})
    # Create graph
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.bar(app_names, max_concurrent_counts, color=colors[:len(app_names)])

    ax.set_xlabel('Application')
    ax.set_ylabel('Max Concurrent TLS Connections')
    ax.set_title('Maximum Concurrent TLS Connections for Different Applications')

    plt.tight_layout()
    plt.show()

'''
Creates a bar chart comparing the usage of different TLS versions between applications.
'''
def create_tls_version_plot(applications):
    app_names = list(applications.keys())
    tls_version_counts = [get_tls_versions(applications[app]) for app in app_names] # Get TLS versions for each application
    tls_versions = ['TLS 1.0 (Deprecated)', 'TLS 1.1 (Deprecated)', 'TLS 1.2', 'TLS 1.3']
    tls_version_usage = {version: [] for version in tls_versions}

    for counts in tls_version_counts:
        for version in tls_versions:
            tls_version_usage[version].append(counts.get(version, 0))

    fig, ax = plt.subplots(figsize=(10, 6))
    bar_width = 0.15
    index = range(len(app_names))
    for i, version in enumerate(tls_versions):
        # Create bars for each TLS version at different positions

        bars = ax.bar(
            [p + bar_width * i for p in index],
            tls_version_usage[version],
            bar_width,
            label=version
        )

        # Add numbers on top of each bar
        for bar in bars:
            height = bar.get_height()
            if height > 0:  # Display only if value is greater than 0
                ax.text(
                    bar.get_x() + bar.get_width() / 2,  # X position
                    height + 1,  # Y position slightly above the bar
                    str(height), # Value to display
                    ha='center',  # Center alignment
                    fontsize=10,  # Font size
                )
    ax.set_xlabel('Application')
    ax.set_ylabel('Number of Packets')
    ax.set_title('TLS Version Usage Comparison Between Applications')
    ax.set_xticks([p + bar_width * (len(tls_versions) / 2 - 0.5) for p in index])
    ax.set_xticklabels(app_names)
    ax.legend()

    plt.show()

'''
  Calculates the average packet length from packets in a given pcap file.
'''
#Packet sizes - D
def calc_avg_packet_length(file_name):
    record = pyshark.FileCapture(file_name, keep_packets=False)
    total_msg_amount = 0
    total_msg_length = 0
    for packet in record:
        total_msg_length=total_msg_length + int(packet.length) # Sum packet lengths
        total_msg_amount = total_msg_amount +1 # Count packets
    return total_msg_length/total_msg_amount

'''
 Calculates the maximum packet length from packets in a given pcap file.
'''
def calc_max_packet_length(file_name):
    record = pyshark.FileCapture(file_name, keep_packets=False)
    max_size=0
    for packet in record:
        if max_size<float(packet.length): # Check for maximum packet length
            max_size=float(packet.length)
    return max_size

'''
 Creates a bar chart comparing the average packet sizes between different applications.
 '''
def avg_packet_size_plots(applications):
    app_names = list(applications.keys())
    length_averages = [calc_avg_packet_length(applications[app]) for app in app_names] # Calculate average packet lengths for each application
    colors = ['#ff7f0e', '#17becf', '#2ca02c', '#d62728', '#1f77b4']
    plt.bar(app_names, length_averages, color=colors, width=0.5)
    plt.xlabel('Application')
    plt.ylabel('Average Msg length (Bytes)')
    plt.title('Average Msg Length Comparison Between Applications')
    for i, v in enumerate(length_averages):
        plt.text(i, v + 0.5, str(round(v, 2)), color='black', ha='center')
    plt.show()

'''
Creates a bar chart comparing the maximum packet sizes between different applications.
'''
def max_packet_size_plots(applications):
    app_names = list(applications.keys())
    max_lengths = [calc_max_packet_length(applications[app]) for app in app_names] # Calculate maximum packet lengths for each application
    colors = ['#ff7f0e', '#17becf', '#2ca02c', '#d62728', '#1f77b4']
    plt.bar(app_names, max_lengths, color=colors, width=0.5)
    plt.xlabel('Application')
    plt.ylabel('Max Msg length (Bytes)')
    plt.title('Max Msg Length Comparison Between Applications')
    for i, v in enumerate(max_lengths):
        plt.text(i, v + 0.5, str(round(v, 2)), color='black', ha='center')
    plt.show()

'''
Creates a scatter plot showing packet sizes over normalized arrival times.
'''
def create_size_per_time(file_name):
    capture = pyshark.FileCapture(file_name, keep_packets=False)
    arrival_times = []
    packet_sizes = []
    start_time = None
    for packet in capture:
        if start_time is None:
            start_time = float(packet.sniff_time.timestamp()) # Record the start time
        arrival_time = float(packet.sniff_time.timestamp()) - start_time # Calculate normalized arrival time
        packet_size = int(packet.length) # Get packet size
        arrival_times.append(arrival_time)
        packet_sizes.append(packet_size)

    plt.scatter(arrival_times, packet_sizes, s=5, color='black')
    plt.xlabel('Normalized Arrival Time')
    plt.ylabel('Packet Size [B]')
    plt.title('Traffic Analysis '+file_name.split('.')[0])
    plt.show()
    capture.close()

'''
 Creates scatter plots for each application showing packet sizes over normalized arrival times.
 '''
def create_size_per_time_plots(applications):
    for a in applications.values():
        create_size_per_time(a)


#Packets inter-arrivals - E
'''
   Calculates the average time between packets in a given pcap file.
'''
def calc_avg_time_between(file_name):
    record = pyshark.FileCapture(file_name, keep_packets=False)
    total_msg_amount = 0
    total_time = 0
    first_packet_time = None
    for packet in record:
        if first_packet_time is None:
            first_packet_time = float(packet.sniff_time.timestamp()) # Record the time of the first packet
        total_time = float(packet.sniff_time.timestamp()) - first_packet_time # Calculate total time
        total_msg_amount = total_msg_amount + 1 # Count the number of packets
    if total_msg_amount == 0:
        return 0
    return  total_time/total_msg_amount # Return the average time between packets

'''
 Creates a bar chart comparing the average time between packets for different applications.
 '''
def create_time_between_packets_plots (applications):
    app_names = list(applications.keys())
    avg_time_between = [calc_avg_time_between(applications[app]) for app in app_names]
    colors = ['#ff7f0e', '#17becf', '#2ca02c', '#d62728', '#1f77b4']
    plt.bar(app_names, avg_time_between, color=colors, width=0.5)
    plt.xlabel('Application')
    plt.ylabel('Time Between Messages')
    plt.title('Time Between Messages Comparison Between Applications')
    for i, v in enumerate(avg_time_between):
        plt.text(i, v + 0.5, str(round(v, 2)), color='black', ha='center')
    plt.show()

#Flow size - F
'''
Calculates the number of packets per second in a given pcap file.
'''
def calculate_packets_per_second(file_name):
    record = pyshark.FileCapture(file_name, keep_packets=False)
    total_msg_amount = 0
    total_time = 0
    first_packet_time = None
    for packet in record:
        if first_packet_time is None:
            first_packet_time=float(packet.sniff_time.timestamp()) # Record the time of the first packet
        total_time=float(packet.sniff_time.timestamp())-first_packet_time # Calculate total time
        total_msg_amount = total_msg_amount + 1 # Count the number of packets
    if total_time == 0:
        return 0
    return total_msg_amount/total_time

'''
  Creates a bar chart comparing the number of packets per second for different applications.
  '''
def packets_per_second_plots(applications):
    app_names = list(applications.keys())
    per_seconds = [calculate_packets_per_second(applications[app]) for app in app_names]
    colors = ['#ff7f0e', '#17becf', '#2ca02c', '#d62728', '#1f77b4']
    plt.bar(app_names, per_seconds, color=colors, width=0.5)
    plt.xlabel('Application')
    plt.ylabel('Average Msg length (Bytes)')
    plt.title('Average Msg Length Comparison Between Applications')
    for i, v in enumerate(per_seconds):
        plt.text(i, v + 0.5, str(round(v, 2)), color='black', ha='center')
    plt.show()

#Flow volume -G
'''
Calculates the number of kilobytes per second in a given pcap file.
'''
def calculate_Kilo_bytes_per_second(file_name):
    record = pyshark.FileCapture(file_name, keep_packets=False)
    total_msg_length = 0
    total_time = 0
    first_packet_time = None
    for packet in record:
        if first_packet_time is None:
            first_packet_time = float(packet.sniff_time.timestamp()) # Record the time of the first packet
        total_time = float(packet.sniff_time.timestamp()) - first_packet_time # Calculate total time
        total_msg_length = total_msg_length + float(packet.length) # Sum the length of all packets
    if total_time == 0:
        return 0
    return total_msg_length/(total_time*1000)  # Return the number of kilobytes per second

'''
   Creates a bar chart comparing the number of kilobytes per second for different applications.
'''
def Kilo_bytes_per_second_plots(applications):
    app_names = list(applications.keys())
    per_seconds = [calculate_Kilo_bytes_per_second(applications[app]) for app in app_names]
    colors = ['#ff7f0e', '#17becf', '#2ca02c', '#d62728', '#1f77b4']
    plt.bar(app_names, per_seconds, color=colors, width=0.5)
    plt.xlabel('Application')
    plt.ylabel('Kilo Bytes Per Second (Bytes)')
    plt.title('Kilo Bytes Per Second Comparison Between Applications')
    for i, v in enumerate(per_seconds):
        plt.text(i, v + 0.5, str(round(v,2)), color='black', ha='center')
    plt.show()


if __name__ == '__main__':
    chrome = 'chrome.pcapng'
    edge = 'edge.pcapng'
    spotify = 'spotify.pcapng'
    youtube = 'youtube.pcapng'
    zoom = 'zoom.pcapng'

    applications = {
        'Chrome': 'chrome.pcapng',
        'Edge': 'edge.pcapng',
        'Spotify': 'spotify.pcapng',
        'YouTube': 'youtube.pcapng',
        'Zoom': 'zoom.pcapng'
    }
    colors = ['#ff7f0e', '#17becf', '#2ca02c', '#d62728', '#1f77b4']
#A - ip header
    #protocol
    create_protocol_plot(chrome)
    create_protocol_plot(edge)
    create_protocol_plot(spotify)
    create_protocol_plot(youtube)
    create_protocol_plot(zoom)
    #ttl
    create_ttl_comparison_plot(applications)
#B - tcp header

    #window size
    create_window_size_comparison_plot(applications)

    # #ports
    for app, filename in applications.items():
        port_filter = 'tcp.port'  # פילטר לסינון חבילות לפי פורט יוצא
        packets = capture_filtered_packets(filename, port_filter)
        port_counts = count_packets_by_src_port(packets)
        port_counts_fill = filter_ports_by_traffic(port_counts, 1.2)
        plot_port_counts(port_counts_fill, app)

#C - TLS
     #by version
    create_tls_version_plot(applications)
# number of parallel connections
    plot_max_concurrent_tls(applications, colors)

#D - packets size
    avg_packet_size_plots(applications)
    max_packet_size_plots(applications)
    create_size_per_time_plots(applications)

#E - time between packets
    create_time_between_packets_plots(applications)

#F - Flow size
    packets_per_second_plots(applications)
#G - Flow volume
    Kilo_bytes_per_second_plots(applications)