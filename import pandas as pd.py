import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE

data = pd.read_csv("HybridAppsDataset.csv")

if 'Unnamed: 0' in data.columns:
    data = data.drop(columns=['Unnamed: 0'])

for col in ['app_hash', 'webview_tab', 'malicious']:
    if col in data.columns and data[col].dtype == 'object':
        data[col] = data[col].astype('category').cat.codes

if 'label' in data.columns:
    data = data.rename(columns={'label': 'malicious'})

target_column = 'malicious'
if target_column not in data.columns:
    raise ValueError(f"The target column '{target_column}' does not exist in the dataset.")

X = data.drop(columns=[target_column])
y = data[target_column]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

smote = SMOTE(random_state=42)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_resampled, y_train_resampled)

feature_importances = pd.Series(model.feature_importances_, index=X.columns)
top_features = feature_importances.nlargest(5).index.tolist()

X = X[top_features]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
model.fit(X_train_resampled, y_train_resampled)

def classify_app(features):
    if len(features) != len(top_features):
        raise ValueError(f"Input features must match the number of top features: {len(top_features)}")
    features_df = pd.DataFrame([features], columns=top_features)
    prediction = model.predict(features_df)[0]
    return "Malicious" if prediction == 1 else "Benign"

def get_user_input():
    print("\nThe following features are required for input (Top 5 Features):")
    print(top_features)
    print("\nEnter the feature values for the app:")
    user_features = []
    for feature in top_features:
        value = input(f"Enter value for {feature}: ")
        try:
            value = float(value)
        except ValueError:
            print(f"Invalid value for {feature}. Please enter a numeric value.")
            return None
        user_features.append(value)
    return user_features

user_input_features = get_user_input()
if user_input_features:
    try:
        result = classify_app(user_input_features)
        print(f"\nThe app is classified as: {result}")
    except ValueError as e:
        print(f"Error: {e}")

example_app = X_test[top_features].iloc[0].tolist()