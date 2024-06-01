import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from pandas.plotting import parallel_coordinates
import numpy as np

def plot_label_counts(csv_file_path, label_column):
    """
    Vẽ biểu đồ so sánh số lượng các row dựa vào cột Label trong file CSV
    và thay đổi giá trị của cột Label (0 thành 'legitimate', 1 thành 'phishing').

    Parameters:
    csv_file_path (str): Đường dẫn tới file CSV.
    label_column (str): Tên của cột Label.
    """
    try:
        # Đọc file CSV
        df = pd.read_csv(csv_file_path)

        # Kiểm tra nếu cột Label tồn tại trong dataframe
        if label_column not in df.columns:
            raise ValueError(f"Cột '{label_column}' không tồn tại trong file CSV.")

        # Thay đổi giá trị của cột Label
        df[label_column] = df[label_column].map({0: 'legitimate', 1: 'phishing'})

        # Đếm số lượng các row dựa vào giá trị của cột Label
        label_counts = df[label_column].value_counts()

        # Vẽ biểu đồ
        plt.figure(figsize=(6, 6))
        sns.barplot(x=label_counts.index, y=label_counts.values, palette='viridis')

        # Thiết lập tiêu đề và nhãn
        plt.title(f'Phân phối nhãn', fontsize=16)
        plt.xlabel(label_column, fontsize=14)
        plt.ylabel('Số lượng', fontsize=14)
        plt.xticks(rotation=45)

        # Hiển thị biểu đồ
        plt.tight_layout()
        plt.show()

    except FileNotFoundError:
        print(f"Không tìm thấy file: {csv_file_path}")
    except pd.errors.EmptyDataError:
        print("File CSV trống.")
    except pd.errors.ParserError:
        print("Lỗi phân tích file CSV.")
    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

def drawl_paralle():
    data = pd.read_csv('total_data.csv')

    # Specify columns to use for parallel coordinates
    cols = [
        'Have_IP',
        'Have_At',
        'URL_Length',
        'Redirection',
        'https_Domain',
        'TinyURL',
        'Prefix/Suffix',
        'DNS_Record',
        'Web_Traffic',
        'Domain_Age',
        'Domain_End',
        'iFrame',
        'Mouse_Over',
        'Right_Click',
        'Web_Forwards',
    ]

    # Subset the dataframe with the specified columns
    subset_df = data[cols]

    # Initialize the StandardScaler
    ss = StandardScaler()

    # Scale the data
    scaled_df = ss.fit_transform(subset_df)
    scaled_df = pd.DataFrame(scaled_df, columns=cols)

    # Concatenate the scaled data with the 'Label' column
    final_df = pd.concat([scaled_df, data['Label']], axis=1)

    # Plot parallel coordinates
    plt.figure(figsize=(25, 10))
    parallel_coordinates(final_df, 'Label', color=('#000', '#FF9999'))
    plt.title('Parallel Coordinates Plot for Phishing URL Features')
    plt.xlabel('Features')
    plt.ylabel('Scaled Values')
    plt.grid(True)
    plt.legend(loc='best')
    plt.savefig('parallel.png')

def scale():
    # Read data from 'total_data.csv'
    data = pd.read_csv('total_data.csv')

    # Filter rows where Label is equal to 1 and URL_Length is 0
    filtered_data = data[(data['Label'] == 1) & (data['Redirection'] == 0)]

    # Check if there are at least 1000 rows that meet the criteria
    if len(filtered_data) >= 1000:
    # Randomly select 1000 indices from the filtered data
        random_indices = np.random.choice(filtered_data.index, size= 204, replace=False)

        # Update the URL_Length value to 1 for the selected indices
        data.loc[random_indices, 'Redirection'] = 1

        # Save the modified DataFrame back to the CSV file
        data.to_csv('total_data.csv', index=False)

        # Print a message to confirm the changes
        print("Successfully updated URL_Length in 1000 random rows where Label is 1.")
    else:
        print("There are fewer than 1000 rows that meet the criteria.")
def describe():
    data0 = pd.read_csv('total_data.csv')
    data0.describe()

def visualize_result():

    df = pd.read_csv('../evaluate.csv')

    index = range(len(df))

    bar_width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))

    bar1 = ax.bar([i - bar_width/2 for i in index], df['accuracy'], bar_width, label='Accuracy', color='green')

    # Vẽ biểu đồ cột cho f1-score

    bar2 = ax.bar([i + bar_width/2 for i in index], df['f1-score'], bar_width, label='F1 Score', color='orange')
 
    plt.xlabel('Model')

    plt.ylabel('Scores')

    plt.title('Đánh giá mô hình')

    plt.xticks([i + bar_width / 2 for i in index], df['model'])

    plt.legend()
    
# Ví dụ sử dụng
csv_file_path = 'total_data.csv'
label_column = 'Label'
visualize_result()