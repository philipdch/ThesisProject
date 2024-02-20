from dash import Dash, dcc, html, Input, Output
import plotly.express as px
import json
from plot_helper import *

def main():
    plot_map = {0: "process_delays", 1: "energy_consumption", 2: "execution_times", 3: "response_times"}
    args = read_args()
    filepath = args.file
    plot_type = args.type
    try:
        file = os.path.split(filepath)[1] 
        plot_id = file.split('_')[-1].split('.')[0]
        data = read_datafile(filepath)
        plot_name = plot_map[plot_type]
        match plot_type:
            case 0:
                fig = processing_time_plot(data)
            case 1:
                fig = energy_plot(data)
            case 2:
                fig = execution_time_plot(data)
            case 3:
                fig = response_time_plot(data)
            case _:
                raise ValueError("Illegal Plot Type")
        fig.update_layout({
                'plot_bgcolor':'#121212',
            }
        )
        filename = plot_name + "_" + plot_id + ".html"
        save_plot(fig, filename)
    except FileNotFoundError:
        print("File " + filepath + " not found.")
    except json.JSONDecodeError:
        print("Invalid JSON format in " + filepath)

if __name__ == "__main__":
    main()