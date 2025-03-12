'''
this page is for the part B of the attacker
'''
import pyshark
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
import nest_asyncio
nest_asyncio.apply()


def extract_features_from_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    sizes = []
    timestamps = []
    for packet in cap:
        try:
            packet_size = int(packet.length)
            timestamp = float(packet.sniff_time.timestamp())
            sizes.append(packet_size)
            timestamps.append(timestamp)
        except AttributeError:
            continue
    return sizes, timestamps


def generate_features_from_sizes_and_times(sizes, timestamps):
    features = []
    labels = []
    timestamps = sorted(timestamps)
    avg_packet_size = np.mean(sizes)
    inter_arrival_times = np.diff(timestamps)
    avg_inter_arrival_time = np.mean(inter_arrival_times) if len(inter_arrival_times) > 0 else 0
    features.append([avg_packet_size, avg_inter_arrival_time])
    label = 'youtube'
    labels.append(label)
    return features, labels


def analyze_traffic(pcap_file, output_csv):
    sizes, timestamps = extract_features_from_pcap(pcap_file)
    features, labels = generate_features_from_sizes_and_times(sizes, timestamps)
    df = pd.read_csv(output_csv)
    new_df = pd.DataFrame(features, columns=['avg_packet_size', 'avg_inter_arrival_time'])
    new_df['label'] = labels
    df = pd.concat([df, new_df], ignore_index=True)
    X = df[['avg_packet_size', 'avg_inter_arrival_time']]
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    scaler = StandardScaler()
    x_train_normal = scaler.fit_transform(X_train)
    x_test_normal = scaler.transform(X_test)
    model = KNeighborsClassifier(n_neighbors=1)
    model.fit(x_train_normal, y_train)
    y_pred = model.predict(x_test_normal)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy * 100:.2f}%")
    df.to_csv(output_csv, index=False)
    return model, df


def print_prediction(model, predict_file, scaler):
    sizes, timestamps = extract_features_from_pcap(predict_file)
    features, labels = generate_features_from_sizes_and_times(sizes, timestamps)
    X_predict = pd.DataFrame(features, columns=['avg_packet_size', 'avg_inter_arrival_time'])
    x_predict_normal = scaler.transform(X_predict)
    predictions = model.predict(x_predict_normal)
    print(f"my prediction is {predictions[0]}")


def make_modle(output_csv):
    df = pd.read_csv(output_csv)
    X = df[['avg_packet_size', 'avg_inter_arrival_time']]
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    scaler = StandardScaler()
    x_train_normal = scaler.fit_transform(X_train)
    x_test_normal = scaler.transform(X_test)
    model = KNeighborsClassifier(n_neighbors=1)
    model.fit(x_train_normal, y_train)
    y_pred = model.predict(x_test_normal)
    accuracy = accuracy_score(y_test, y_pred)
    return model, scaler

def test_model_accuracy(data_file_name,check):
    df = pd.read_csv(data_file_name)
    X = df[['avg_packet_size', 'avg_inter_arrival_time']]
    y = df['label']
    amount_of_check = check
    total_accuracy = 0
    for i in range(0, amount_of_check):
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.16)
        scaler = StandardScaler()
        x_train_normal = scaler.fit_transform(X_train)
        x_test_normal = scaler.transform(X_test)
        model = KNeighborsClassifier(n_neighbors=1)
        model.fit(x_train_normal, y_train)
        y_pred = model.predict(x_test_normal)
        accuracy = accuracy_score(y_test, y_pred)
        total_accuracy += accuracy
        if i%1000==0:
            print(f"I is {i}")
    total_accuracy = total_accuracy / amount_of_check
    print(f"Accuracy: {total_accuracy * 100:.2f}%")
def add_to_csv(data_file_name,files_array):
    for pcap_file in files_array:
        analyze_traffic(pcap_file,data_file_name)

def print_Bonus_prediction(pcap_file,data_file_name):
    model,scaler = make_modle(data_file_name)
    print_prediction(model,pcap_file,scaler)

if __name__ == "__main__":
    output_csv = 'part_b_data.csv'
    # we used the comments below to build our csv with data
    # for training
    #
    # chrome_files = ['chrome.pcapng', 'chrome2.pcapng', 'chrome3.pcapng', 'chrome4.pcapng', 'chrome5.pcapng',
    #                 'chrome6.pcapng', 'chrome7.pcapng', 'chrome8.pcapng', 'chrome9.pcapng', 'chrome10.pcapng',
    #                 'chrome11.pcapng', 'chrome12.pcapng', 'chrome13.pcapng', 'chrome14.pcapng', 'chrome15.pcapng',
    #                 'chrome16.pcapng', 'chrome17.pcapng', 'chrome18.pcapng', 'chrome19.pcapng', 'chrome20.pcapng',
    #                 'chrome21.pcapng', 'chrome22.pcapng', 'chrome23.pcapng', 'chrome24.pcapng', 'chrome25.pcapng']
    # youtube_files = ['youtube.pcapng', 'youtube2.pcapng', 'youtube3.pcapng', 'youtube4.pcapng', 'youtube5.pcapng',
    #                  'youtube6.pcapng', 'youtube7.pcapng', 'youtube8.pcapng', 'youtube9.pcapng', 'youtube10.pcapng',
    #                  'youtube11.pcapng', 'youtube12.pcapng', 'youtube13.pcapng', 'youtube14.pcapng', 'youtube15.pcapng',
    #                  'youtube16.pcapng', 'youtube17.pcapng', 'youtube18.pcapng', 'youtube19.pcapng', 'youtube20.pcapng',
    #                  'youtube21.pcapng', 'youtube22.pcapng', 'youtube23.pcapng', 'youtube24.pcapng', 'youtube25.pcapng']
    #
    # zoom_files = ['zoom.pcapng', 'zoom2.pcapng', 'zoom3.pcapng', 'zoom4.pcapng', 'zoom5.pcapng', 'zoom6.pcapng',
    #               'zoom7.pcapng', 'zoom8.pcapng', 'zoom9.pcapng', 'zoom10.pcapng', 'zoom11.pcapng', 'zoom12.pcapng',
    #               'zoom13.pcapng', 'zoom14.pcapng', 'zoom15.pcapng', 'zoom16.pcapng', 'zoom17.pcapng', 'zoom18.pcapng',
    #               'zoom19.pcapng', 'zoom20.pcapng', 'zoom21.pcapng', 'zoom22.pcapng', 'zoom23.pcapng', 'zoom24.pcapng',
    #               'zoom25.pcapng']
    # spotify_files = ['spotify.pcapng', 'spotify2.pcapng', 'spotify3.pcapng', 'spotify4.pcapng', 'spotify5.pcapng',
    #                  'spotify6.pcapng', 'spotify7.pcapng', 'spotify8.pcapng', 'spotify9.pcapng', 'spotify10.pcapng',
    #                  'spotify11.pcapng', 'spotify12.pcapng', 'spotify13.pcapng', 'spotify14.pcapng', 'spotify15.pcapng',
    #                  'spotify16.pcapng', 'spotify17.pcapng', 'spotify18.pcapng', 'spotify19.pcapng', 'spotify20.pcapng',
    #                  'spotify21.pcapng', 'spotify22.pcapng', 'spotify23.pcapng', 'spotify24.pcapng', 'spotify25.pcapng']
    # edge_files = ['edge.pcapng', 'edge2.pcapng', 'edge3.pcapng', 'edge4.pcapng', 'edge5.pcapng',
    #               'edge6.pcapng', 'edge7.pcapng', 'edge8.pcapng', 'edge9.pcapng', 'edge10.pcapng',
    #               'edge11.pcapng', 'edge12.pcapng', 'edge13.pcapng', 'edge14.pcapng', 'edge15.pcapng',
    #               'edge16.pcapng', 'edge17.pcapng', 'edge18.pcapng', 'edge19.pcapng', 'edge20.pcapng'
    #     , 'edge21.pcapng', 'edge22.pcapng', 'edge23.pcapng', 'edge24.pcapng', 'edge25.pcapng']
    #
    # add_to_csv(output_csv,edge_files)
    ###################

    ################
    print("Enter the number that you want \n\t1 for testing model accuracy\n\t2 for testing bonus prediction\n\t3 for testing prediction")

    try:
        x = int(input())
        if x == 1:
            test_model_accuracy(output_csv, 10000)
        if x == 2:
            print("if you want your pcap enter 1 else enter any other number")
            y = int(input())
            if y == 1:
                print("Please enter pcap file name: (make sure that the file in the same directory as this script)")
                file_name = input()
            else:
                file_name = 'spotify_and_gmail.pcapng'
            print_Bonus_prediction(file_name, output_csv)
        if x == 3:
            print("Please enter pcap file name: (make sure that the file in the same directory as this script)")
            file_name = input()
            new_model, sc = make_modle(output_csv)
            print_prediction(new_model, file_name, sc)
    except ValueError:
        print("you didnt enter number")
    except FileNotFoundError:
        print("there is no such file")
    except Exception as e:
        print("an error has happend")
    ##################