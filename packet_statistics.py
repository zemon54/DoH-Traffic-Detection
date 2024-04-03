import pyshark
import pandas as pd
from scipy.stats import skew

# skewness
def calculate_skew(data):
    return skew(data)

# Read wireshark pcapng file
capture = pyshark.FileCapture('C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\wireshark_capture_1.pcapng')

# Initializations
source_ips = []
destination_ips = []
source_ports = []
destination_ports = []
timestamps = []
packet_lengths = []
packet_times = []

# Part 1: Extract the required fields from the pcapng file
# Iterate over each packet
# Depending on Packet Type extract the required fields 
for packet in capture:
    if 'IP' in packet:
        if 'TCP' in packet or 'UDP' in packet:
            source_ips.append(packet.ip.src)
            destination_ips.append(packet.ip.dst)
            timestamps.append(float(packet.sniff_timestamp))
            if 'TCP' in packet:
                source_ports.append(packet.tcp.srcport)
                destination_ports.append(packet.tcp.dstport)
            elif 'UDP' in packet:
                source_ports.append(packet.udp.srcport)
                destination_ports.append(packet.udp.dstport)
            
            # Calculate packet length
            try:
                packet_lengths.append(int(packet.length))
            except AttributeError:
                packet_lengths.append(0) 

            # Calculate inter-arrival time
            try:
                previous_timestamp = timestamps[-2] if len(timestamps) > 1 else timestamps[0]
                inter_arrival_time = float(packet.sniff_timestamp) - previous_timestamp
                packet_times.append(inter_arrival_time)
            except AttributeError:
                packet_times.append(0) 

# DataFrame from extracted data
df = pd.DataFrame({
    'SourceIP': source_ips,
    'DestinationIP': destination_ips,
    'SourcePort': source_ports,
    'DestinationPort': destination_ports,
    'TimeStamp': timestamps,
    'PacketLength': packet_lengths,
    'PacketTime': packet_times
})

# Convert TimeStamp string to datetime format
df['TimeStamp'] = pd.to_datetime(df['TimeStamp'], unit='s')

# Part 2: Calculate the statistics for each column

# Group by SourceIP and DestinationIP
grouped = df.groupby(['SourceIP', 'DestinationIP'])

# Calculate statistics for each group
# PacketLength statistics
df['PacketLengthVariance'] = grouped['PacketLength'].transform('var')
df['PacketLengthStandardDeviation'] = grouped['PacketLength'].transform('std')
df['PacketLengthMean'] = grouped['PacketLength'].transform('mean')
df['PacketLengthMedian'] = grouped['PacketLength'].transform('median')
df['PacketLengthMode'] = grouped['PacketLength'].transform(lambda x: x.mode()[0] if not x.mode().empty else 0)
df['PacketLengthSkewFromMedian'] = grouped['PacketLength'].transform(lambda x: (x - x.median()).skew())
df['PacketLengthSkewFromMode'] = grouped['PacketLength'].transform(lambda x: (x - x.mode()[0]).skew() if not x.mode().empty else 0)
df['PacketLengthCoefficientofVariation'] = df['PacketLengthStandardDeviation'] / df['PacketLengthMean']

# Repeat for PacketTime
df['PacketTimeVariance'] = grouped['PacketTime'].transform('var')
df['PacketTimeStandardDeviation'] = grouped['PacketTime'].transform('std')
df['PacketTimeMean'] = grouped['PacketTime'].transform('mean')
df['PacketTimeMedian'] = grouped['PacketTime'].transform('median')
df['PacketTimeMode'] = grouped['PacketTime'].transform(lambda x: x.mode()[0] if not x.mode().empty else 0)
df['PacketTimeSkewFromMedian'] = grouped['PacketTime'].transform(lambda x: (x - x.median()).skew())
df['PacketTimeSkewFromMode'] = grouped['PacketTime'].transform(lambda x: (x - x.mode()[0]).skew() if not x.mode().empty else 0)
df['PacketTimeCoefficientofVariation'] = df['PacketTimeStandardDeviation'] / df['PacketTimeMean']

# Duration
df['Duration'] = grouped['TimeStamp'].transform(lambda x: (x.max() - x.min()).total_seconds())

# FlowBytesSent for each flow
df['FlowBytesSent'] = grouped['PacketLength'].transform('sum')

# FlowBytesReceived for each flow
df['FlowBytesReceived'] = df.groupby(['DestinationIP', 'DestinationPort', 'SourceIP', 'SourcePort'])['PacketLength'].transform('sum')

# FlowSentRate for each flow
df['FlowSentRate'] = df['FlowBytesSent'] / df['Duration']

# FlowReceivedRate for each flow
df['FlowReceivedRate'] = df['FlowBytesReceived'] / df['Duration']

# Calculate ResponseTime statistics
grouped = df.groupby(['SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort'])
df['ResponseTimeTimeVariance'] = grouped['PacketTime'].transform('var')
df['ResponseTimeTimeStandardDeviation'] = grouped['PacketTime'].transform('std')
df['ResponseTimeTimeMean'] = grouped['PacketTime'].transform('mean')
df['ResponseTimeTimeMedian'] = grouped['PacketTime'].transform('median')
df['ResponseTimeTimeMode'] = grouped['PacketTime'].transform(lambda x: x.mode()[0] if not x.mode().empty else 0)
df['ResponseTimeTimeSkewFromMedian'] = grouped['PacketTime'].transform(lambda x: (x - x.median()).skew())
df['ResponseTimeTimeSkewFromMode'] = grouped['PacketTime'].transform(lambda x: (x - x.mode()[0]).skew() if not x.mode().empty else 0)
df['ResponseTimeTimeCoefficientofVariation'] = df['ResponseTimeTimeStandardDeviation'] / df['ResponseTimeTimeMean']

# Reorder columns
final_columns_sequence = [
    'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort', 'TimeStamp',
    'Duration', 'FlowBytesSent', 'FlowSentRate', 'FlowBytesReceived', 'FlowReceivedRate',
    'PacketLengthVariance', 'PacketLengthStandardDeviation', 'PacketLengthMean',
    'PacketLengthMedian', 'PacketLengthMode', 'PacketLengthSkewFromMedian',
    'PacketLengthSkewFromMode', 'PacketLengthCoefficientofVariation',
    'PacketTimeVariance', 'PacketTimeStandardDeviation', 'PacketTimeMean',
    'PacketTimeMedian', 'PacketTimeMode', 'PacketTimeSkewFromMedian',
    'PacketTimeSkewFromMode', 'PacketTimeCoefficientofVariation',
    'ResponseTimeTimeVariance', 'ResponseTimeTimeStandardDeviation',
    'ResponseTimeTimeMean', 'ResponseTimeTimeMedian', 'ResponseTimeTimeMode',
    'ResponseTimeTimeSkewFromMedian', 'ResponseTimeTimeSkewFromMode',
    'ResponseTimeTimeCoefficientofVariation'
]

# Reorder columns
df = df[final_columns_sequence]

# Save DataFrame as CSV
df.to_csv('C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\output_1.csv', index=False)
