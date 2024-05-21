import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from pandas.plotting import parallel_coordinates

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
def showDistribution():
    data0 = pd.read_csv('total_data.csv')
    data0.hist(bins=50, figsize=(15, 15))
    plt.tight_layout()  # Automatically adjust subplot parameters to give specified padding
    plt.savefig('distribution.png')
    plt.show()

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



# Ví dụ sử dụng
csv_file_path = 'total_data.csv'
label_column = 'Label'
drawl_paralle()