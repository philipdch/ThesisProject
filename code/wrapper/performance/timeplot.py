import sys 
import os
import json
import matplotlib.pyplot as plt

def read_data(filepath):
    with open(filepath, 'r') as file:
        data = json.load(file)
    return data

def create_graph(data, plot_id):
    packets = []
    execution_times = []
    packet_time_diffs = []

    for packet_info in data:
        packets.append(packet_info['id'])
        
        if(packet_info['func_exec_time'] is not None):
            func_exec_time = round(packet_info['func_exec_time'], 2)
            execution_times.append(1000 * func_exec_time)
        else:
            execution_times.append(0)
        sent_time = packet_info['sent_time']
        received_time = packet_info['received_time']
        
        # Calculate the time difference between sent_time and received_time
        time_diff = round(1000 * (sent_time - received_time), 2)
        packet_time_diffs.append(time_diff)

    # Plotting the data
    fig, exec_axis = plt.subplots()
    pkt_times_axis = exec_axis.twinx()
    exec_axis.plot(packets, execution_times, marker='.', color='g', markersize=10, linestyle='dotted', label='Function Execution Time')
    pkt_times_axis.plot(packets, packet_time_diffs, marker='.', color='b', markersize=10, linestyle='dotted', label='Send Time - Arrival Time')

    exec_axis.set_xlabel('Packet ID')
    exec_axis.set_ylabel('Wrapper execution time (ms)', color='g')
    pkt_times_axis.set_ylabel('Packet Processing time (ms)', color='b')
    plt.title('Wrapper Processing Times')
    try:
        plt.savefig("./plots/plot_" + plot_id + ".png")
    except FileNotFoundError:
        print("Could not save plot")

def main():
    if len(sys.argv) != 2:
        print("You must specify the json file from which to read plot data")
        sys.exit(1)

    filepath = sys.argv[1]
    try:
        data = read_data(filepath)
        file = os.path.split(filepath)[1] 
        plot_id = file.split('_')[1].split('.')[0]
        create_graph(data, plot_id)
    except FileNotFoundError:
        print("File " + filepath + " not found.")
    except json.JSONDecodeError:
        print("Invalid JSON format in " + filepath)

if __name__ == "__main__":
    main()