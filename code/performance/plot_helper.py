import os
import pandas as pd
import plotly.express as px
import argparse

def to_milliseconds(value):
    return round(1000 * value, 2)

def read_datafile(filepath):
    filename, extension = os.path.splitext(filepath)
    if extension == ".json":
        return pd.read_json(filepath)
    elif extension == ".csv":
        return pd.read_csv(filepath, sep=r'[,;]', engine='python')
    else:
        raise ValueError("Unsupported file type")

def incremental_id(df):
   df['id'] = range(len(df))
   return df

def processing_time_plot(df):
    df['processing_delay'] = df['processing_delay'].apply(to_milliseconds)
    avg_delay = df["processing_delay"].mean()
    fig = px.scatter(df, x="id", y="processing_delay", hover_data=['packet', 'received_time'],
                     color="processing_delay", color_continuous_scale=px.colors.sequential.Sunsetdark,
                     title="Packet Processing Delays")  
    fig.update_layout(
        xaxis_title="Packet ID",
        yaxis_title="Processing Delay (ms)"
    )
    fig.add_hline(y=avg_delay, line_color="#19D3F3")

    fig.add_annotation(x=df["id"].max(), y=avg_delay,
                text=f"<b>Avg Delay = {avg_delay:.2f} ms</b>",
                showarrow=False, yanchor='top',
                xanchor='left', font=dict(color="white", size=15))
    return fig

def energy_plot(df):
    colorscale = [
        [0, '#7EE07E'], 
        [0.2, '#D9EF8B'],  
        [0.4, '#FFBF00'],
        [0.6, '#FF7F50'], 
        [0.8, '#DE3163'], 
        [1, '#F74D4D'] 
    ]
    df = incremental_id(df)  
    fig = px.scatter(df, x="id", y="package_0", hover_data=['timestamp', 'dram_0', 'core_0'],
                     color="package_0", color_continuous_scale=colorscale,
                     title="Wrapper energy consumption per packet")  
    fig.update_layout(
        xaxis_title="Packet ID",
        yaxis_title="Energy Consumption"
    )
    return fig

def execution_time_plot(df):
    df['duration'] = df['duration'].apply(to_milliseconds)
    avg_delay = df["duration"].mean()
    df = incremental_id(df)  
    fig = px.scatter(df, x="id", y="duration", hover_data=['timestamp'],
                     color="duration", color_continuous_scale=px.colors.sequential.Sunsetdark,
                     title="Wrapper funcion execution times")  
    fig.update_layout(
        xaxis_title="Packet ID",
        yaxis_title="Execution Time (ms)"
    )
    fig.add_hline(y=avg_delay, line_color="#19D3F3")

    fig.add_annotation(x=df["id"].max(), y=avg_delay,
                text=f"<b>Avg Execution Time = {avg_delay:.2f} ms</b>",
                showarrow=False, yanchor='top',
                xanchor='left', font=dict(color="white", size=15))
    return fig

def response_time_plot(df):
    df['response_time'] = df['response_time'].apply(to_milliseconds)
    avg_time = df["response_time"].mean()
    df = df.rename(columns={'id': 'timestamp'})
    df = incremental_id(df)  
    fig = px.scatter(df, x="id", y="response_time", hover_data=['timestamp', 'server', 'command'], 
                     color="response_time", color_continuous_scale=px.colors.sequential.Sunsetdark,
                     title="Response times per request")  
    fig.update_layout(
        xaxis_title="Packet ID",
        yaxis_title="Response Time (ms)"
    )
    fig.add_hline(y=avg_time, line_color="#19D3F3")

    fig.add_annotation(x=df["id"].max(), y=avg_time,
                text=f"<b>Avg Response Time = {avg_time:.2f} ms</b>",
                showarrow=False, yanchor='top',
                xanchor='left', font=dict(color="white", size=15))
    return fig

def save_plot(fig, filename):
    current_dir = os.path.dirname(os.path.realpath(__file__))
    subdir_path = os.path.join(current_dir, 'plots')
    if not os.path.exists(subdir_path):
        os.makedirs(subdir_path)

    filepath = os.path.join(subdir_path, filename)
    try:
        fig.write_html(filepath)
    except FileNotFoundError:
        print("Could not save plot")

def read_args():
    parser = argparse.ArgumentParser(description='Plot data based on given file.')

    parser.add_argument('-f', '--file', required=True, help='Data file.')
    parser.add_argument('-t', '--type', type=int, choices=[0, 1, 2, 3], required=True, 
                        help='Specify plot type (0=Processing Delay, 1=Energy COnsumption, 2=Function Execution Time, 3=Response Time).')

    args = parser.parse_args()

    return args
