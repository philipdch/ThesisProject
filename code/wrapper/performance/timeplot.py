import sys 
import os
import json
import csv
import matplotlib.pyplot as plt
import numpy as np
import argparse

PLOT_ID = ""

def read_data(filepath, plot_type):
    with open(filepath, 'r') as file:
        filename, extension = os.path.splitext(filepath)
        if extension == ".json":
            data = json.load(file)
        elif extension == ".csv":
            data = csv.reader(file, delimiter=';')
            next(data, None)
        if(plot_type == 'time'):
            return plot_time(data)
        elif(plot_type == 'energy'):
            return plot_energy(data)
    return None

def plot_energy(data):
    pkts = []
    func_duration = []
    energy_consumption = []
    
    i=0
    for row in data:
        if len(row) < 6:
            continue

        duration = round(1000 * float(row[2]), 2)
        if(duration >= 2):
            pkts.append(i)
            i = i + 1
            func_duration.append(duration)
            energy_consumption.append(row[3])
    return (np.array(pkts), np.array(func_duration), np.array(energy_consumption).astype(np.double))

def plot_time(data):
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

    return (np.array(pkts), np.array(proc_times), np.array(exec_times))

def create_graph(data, plot_type):
    if(plot_type == "time"):
        y1label = 'Wrapper Execution Time (ms)'
        y2label = 'Packet Processing Time (ms)'
        title = 'Packet Processing and Execution Times'
    elif(plot_type == "energy"):
        y1label = 'Function Duration (ms)'
        y2label = 'Energy Consumption'
        title = "Function Execution Durations and Consumed Energy"

    packets = data[0]
    print(packets)
    print(data[1])
    print(data[2])
    processing_avg = np.average(data[1])

    fig, (axis1, axis2) = plt.subplots(2, 1, gridspec_kw={'hspace': 0.5})
    axis1.plot(packets, data[1], 'go--')
    axis1.set_xlabel("Packet ID")
    axis1.set_ylabel(y1label, color='g')
    axis1.tick_params('y', colors='g')
    axis1.legend()

    axis1.text(0.5, 0.95, f'Avg Processing Time: {processing_avg:.2f} ms', transform=axis1.transAxes, ha='center', va='center', color='r')

    axis2.plot(packets, data[2], 'bo--')
    axis2.set_xlabel("Packet ID")
    axis2.set_ylabel(y2label, color='b')
    axis2.tick_params('y', colors='b')
    axis2.legend()
    
    y1max = np.ceil(np.nanmax(data[1]) / 5) * 5 + 20
    y2max = np.ceil(np.nanmax(data[2]) / 5) * 5 + 20
    axis1.set_ylim(0, y1max)
    axis2.set_ylim(0, y2max)

    fig.suptitle(title)

    save_plot(plot_type)

def save_plot(plot_name):
    current_dir = os.path.dirname(os.path.realpath(__file__))
    filename = plot_name + "_plot_" + PLOT_ID + ".png"
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
    plot_map = {0: 'time', 1: 'energy'}

    parser = argparse.ArgumentParser(description='Plot data based on given file.')

    parser.add_argument('-f', '--file', required=True, help='Data file.')
    parser.add_argument('-t', '--type', type=int, choices=[0, 1], required=True, help='Specify plot type (0=time, 1=energy).')

    args = parser.parse_args()

    filepath = args.file
    plot_type = plot_map[args.type]

    try:
        file = os.path.split(filepath)[1] 
        global PLOT_ID
        PLOT_ID = file.split('_')[-1].split('.')[0]
        data = read_data(filepath, plot_type)
        create_graph(data, plot_type)
    except FileNotFoundError:
        print("File " + filepath + " not found.")
    except json.JSONDecodeError:
        print("Invalid JSON format in " + filepath)

if __name__ == "__main__":
    main()