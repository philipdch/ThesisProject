import sys 
import os
import json
import matplotlib.pyplot as plt
import numpy as np

def read_data(filepath):
    with open(filepath, 'r') as file:
        data = json.load(file)
    return data

def create_graph(data, plot_id):
    pkts = []
    exec_times = []
    proc_times = []

    for packet_info in data:
        pkts.append(packet_info['id'])
        
        if(packet_info['func_exec_time'] is not None):
            func_exec_time = round(1000 * packet_info['func_exec_time'], 2)
            exec_times.append(func_exec_time)
        else:
            exec_times.append(np.nan)

        # Calculate the time difference between sent_time and received_time
        sent_time = packet_info['sent_time']
        received_time = packet_info['received_time']
        time_diff = round(1000 * (sent_time - received_time), 2)
        proc_times.append(time_diff)

    packets = np.array(pkts)
    execution_times = np.array(exec_times)
    processing_times = np.array(proc_times)

    max = np.nanmax(np.maximum(execution_times, processing_times))
    max = np.ceil(max / 5) * 5 + 10

    processing_avg = np.average(processing_times)

    # Plotting the data
    fig, exec_axis = plt.subplots()
    exec_axis.plot(packets, execution_times, 'go--', label='Wrapper Execution Time (ms)')
    exec_axis.set_xlabel('Packet ID')
    exec_axis.set_ylabel('Wrapper Execution Time (ms)', color='g')
    exec_axis.tick_params('y', colors='g')

    exec_axis.text(0.5, 0.95, f'Avg Processing Time: {processing_avg:.2f} ms', transform=exec_axis.transAxes, ha='center', va='center', color='r')

    pkt_times_axis = exec_axis.twinx()
    pkt_times_axis.plot(packets, processing_times, 'bo--', label='Pcket Processing Time (ms)')
    pkt_times_axis.set_ylabel('Packet Processing Time (ms)', color='b')
    pkt_times_axis.tick_params('y', colors='b')

    exec_axis.set_ylim(0, max)
    pkt_times_axis.set_ylim(0, max)

    plt.title('Packet Processing and Execution Times')

    print(packets)
    print(execution_times)
    print(processing_times)

    current_dir = os.path.dirname(os.path.realpath(__file__))
    filename = "plot_" + plot_id + ".png"
    subdir_path = os.path.join(current_dir, 'plots')
    if not os.path.exists(subdir_path):
        os.makedirs(subdir_path)

    filepath = os.path.join(subdir_path, filename)
    try:
        print(filepath)
        plt.savefig(filepath)
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