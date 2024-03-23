import os 
import sys
# sys.path.append(r'C:\Users\SyedAliZaminGilani\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Lib\site-packages')
sys.path.append(r'C:\Users\SyedAliZaminGilani\Desktop\Semester2\computernetworksproject\dohdetection\Lib\site-packages')
import joblib
# from tqdm import tqdm
import numpy as np
# sys.path.append(r'C:\Users\SyedAliZaminGilani\Desktop\Semester2\computernetworksproject\dohdetection\Lib\site-packages')
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.utils import shuffle
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

epochs = 10

# Progress bar initialization

#####

df1_benign_df = pd.read_csv("C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\maindataset\\benign-csvs\\benign-chrome.csv", delimiter=',')
df2_benign_df = pd.read_csv("C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\maindataset\\benign-csvs\\benign-firefox.csv", delimiter=',')

# df_concatenated = pd.concat([df1_benign_df, df2_benign_df], ignore_index=True)

df_concatenated = pd.concat([df1_benign_df, df2_benign_df])
# Reset index
df1_benign = df_concatenated.reset_index(drop=True)

df1_benign['DoH'] = 0 # benign
df1_benign = df1_benign.rename(columns={'DoH': 'labels'})

df1_malic_df = pd.read_csv("C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\maindataset\\malic-csvs\\mal-iodine.csv", delimiter=',')
df2_malic_df = pd.read_csv("C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\maindataset\\malic-csvs\\mal-dns2tcp.csv", delimiter=',')
df3_malic_df = pd.read_csv("C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\maindataset\\malic-csvs\\mal-dnscat2.csv", delimiter=',')

df_concatenated = pd.concat([df1_malic_df, df2_malic_df])
df1_malic_df2 = df_concatenated.reset_index(drop=True)

df_concatenated = pd.concat([df1_malic_df2, df3_malic_df])
# Reset index after dropping duplicate headers
df1_malic = df_concatenated.reset_index(drop=True)

# # df1_malic.append(df2_malic)
# df1_malic.append(df3_malic)
df1_malic['DoH'] = 1 # malicious
df1_malic = df1_malic.rename(columns={'DoH': 'labels'})
print("DF1 BENIGN")
print("Number of rows:", df1_benign.shape[0])
print("Number of columns:", df1_benign.shape[1])
print(df1_benign.head())
print(df1_benign.tail())
print("DF1 MALIC")
print("Number of rows:", df1_malic.shape[0])
print("Number of columns:", df1_malic.shape[1])
print(df1_malic.head())
print(df1_malic.tail())
#####
df_concatenated = pd.concat([df1_benign, df1_malic])
# Reset index after dropping duplicate headers
data_to_shuffle = df_concatenated.reset_index(drop=True)
data = shuffle(data_to_shuffle)
print("DATA")
print("Number of rows:", data.shape[0])
print("Number of columns:", data.shape[1])
print(data.head())
print(data.tail())
####
data.isnull().sum()
#####
data = data.dropna()
#####
data.isnull().sum()
#####
# print(data.describe())
######
counts = data.labels.value_counts()
print(counts)
########
sns.countplot(x='labels', data=data);
# plt.show()
########
counts = data.SourcePort.value_counts()
# print("Sourceport")
# print(counts)

##### Data preprocessing
le=LabelEncoder()
data['SourceIP'] = le.fit_transform(data['SourceIP'])
data['DestinationIP'] = le.fit_transform(data['DestinationIP'])
data['SourcePort'] = le.fit_transform(data['SourcePort'])
data['DestinationPort'] = le.fit_transform(data['DestinationPort'])

X = data.drop(["TimeStamp","labels"],axis=1)
y = data['labels'].values

scaler = StandardScaler()
X = scaler.fit_transform(X)

# ###### Data Splitting

X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.3, random_state=3)

# ###### Function

def func(model):
    print("Starting model training")
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    acc = accuracy_score(pred, y_test)
    print('Test Accuracy : \033[32m \033[01m {:.5f}% \033[30m \033[0m'.format(acc*100))
    print(classification_report(y_test, pred))
    cf_matrix = confusion_matrix(y_test, pred)
    cf_matrix_normalized = cf_matrix / np.sum(cf_matrix)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cf_matrix/np.sum(cf_matrix), annot=True, fmt='0.2%')
    plt.title('Normalized Confusion Matrix')
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.show()
    return model

# ###### Training using Random Forest Classifier
# from sklearn.ensemble import RandomForestClassifier
# for _ in tqdm(range(epochs), desc="Training progress", unit="epoch"):
#     acc_RFC = func(RandomForestClassifier())
#     print(acc_RFC)

# ###### Training using Decision Tree classifier
# from sklearn.tree import DecisionTreeClassifier
# acc_DTC = func(DecisionTreeClassifier())

# ##### Training using SGD Classifier
# from sklearn.linear_model import SGDClassifier
# acc_SGDC=func(SGDClassifier())

# ###### Training using KNeighbors Classifier
from sklearn.neighbors import KNeighborsClassifier
acc_KN = func(KNeighborsClassifier())
joblib.dump(acc_KN, "knn_model.pkl")

# #### Training using Gausian NB
# from sklearn.naive_bayes import GaussianNB
# acc_GNB = func(GaussianNB())

# ###### Training using ExtrA Tree Classifier
# from sklearn.ensemble import ExtraTreesClassifier
# acc_ETC = func(ExtraTreesClassifier())

# ###### Training using Adaboost Classifier
# from sklearn.ensemble import AdaBoostClassifier
# acc_ABC=func(AdaBoostClassifier())

# #### Final Report
# output = pd.DataFrame({"Model":['Random Forest Classifier','Decision Tree Classifier','SGD Classifier',
#                                 'KNeighbors Classifier','Gaussian NB','Extra Trees Classifier','Adaboost Classifier'],
#                       "Accuracy":[acc_RFC, acc_DTC, acc_SGDC, acc_KN, acc_GNB, acc_ETC,acc_ABC]})


# #### Display in Graph
# plt.figure(figsize=(12, 6))
# plots = sns.barplot(x='Model', y='Accuracy', data=output)
# for bar in plots.patches:
#     plots.annotate(format(bar.get_height(), '.2f'),
#                    (bar.get_x() + bar.get_width() / 2,
#                     bar.get_height()), ha='center', va='center',
#                    size=15, xytext=(0, 8),
#                    textcoords='offset points')

# plt.xlabel("Models")
# plt.xticks(rotation=30);
# plt.ylabel("Accuracy")
# plt.show()