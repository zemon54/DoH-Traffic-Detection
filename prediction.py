import os 
import sys
import pandas as pd
sys.path.append(r'C:\Users\SyedAliZaminGilani\Desktop\Semester2\computernetworksproject\dohdetection\Lib\site-packages')
import joblib
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

# Load the trained model from the .pkl file
model = joblib.load('C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\knn_model.pkl')
# model = joblib.load('C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\maindataset\\test.xlsx', encoding='latin1')
# Load the CSV file
csv_file_path = r"C:\\Users\\SyedAliZaminGilani\\Desktop\\Semester2\\computernetworksproject\\maindataset\\benign-csvs\\test_data.csv"
data = pd.read_csv(csv_file_path)
data_1 = data.reset_index(drop=True)
data_1 = data_1.rename(columns={'DoH': 'labels'})

data = shuffle(data_1)
data = data.dropna()
sns.countplot(x='labels', data=data);
plt.show()

le=LabelEncoder()
# data = data.rename(columns={'DoH': 'labels'})
data['SourceIP'] = le.fit_transform(data['SourceIP'])
data['DestinationIP'] = le.fit_transform(data['DestinationIP'])
data['SourcePort'] = le.fit_transform(data['SourcePort'])
data['DestinationPort'] = le.fit_transform(data['DestinationPort'])
X = data.drop(["TimeStamp","labels"],axis=1)
# Preprocess the data if necessary
# For example, you might need to perform feature scaling or encoding
# prediction_data = prediction_data.drop(["TimeStamp"], axis=1)
# Make predictions
scaler = StandardScaler()
X_test = scaler.fit_transform(X)
predictions = model.predict(X_test)

# Do something with the predictions, for example, save them to a new CSV file
predictions_df = pd.DataFrame(predictions, columns=['Predicted_Label'])
predictions_df.to_csv('predictions.csv', index=False)

print("Predictions saved to predictions.csv")
