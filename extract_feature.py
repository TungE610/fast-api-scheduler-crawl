import pandas as pd
from extract_features import phishingFeatureExtraction

def feature_extraction():
    phishing_url = pd.read_csv("file/phishing_tank_20240519_225602.csv")
    phish_features = []

    # Extract features for each URL in the range specified
    for i in range(3801, 4000):
        url = phishing_url['url'][i]
        print(i)
        
        phish_features.append(phishingFeatureExtraction(url, 1))
        
    # Define the feature names
    feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
                    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                    'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards', 'Label']

    # Create a DataFrame with the extracted features
    phishing_df = pd.DataFrame(phish_features, columns=feature_names)

    # Save the DataFrame to a new CSV file
    phishing_df.to_csv("new.csv", mode='a', header=True, index=False)

    print("Feature extraction and CSV creation completed successfully.")
    
feature_extraction()